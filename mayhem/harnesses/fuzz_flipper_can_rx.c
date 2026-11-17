/*
 * fuzz_flipper_can_rx.c — Flipper Zero app CAN receive path.
 *
 * Feeds a stream of CAN frames, as read_can_message() (libraries/mcp_can_2515.c)
 * hands them over, through the protocol handlers of fsd_logic/fsd_handler.c in
 * the order the worker loop in scenes/fsd_running.c calls them. That loop needs
 * the Flipper SDK (furi, SPI, storage), so its dispatch is mirrored here; the
 * SPI sends are left out and the SD capture line is formatted into a buffer.
 *
 * Input: FSD_FUZZ_CFG_LEN config bytes (fsd_fuzz_state.h), then records of
 * FSD_FUZZ_REC_LEN: id (LE u16; the driver keeps 16 bits), flags (bits2-7
 * dt*8ms), dlc (the driver masks it to 4 bits and clamps it to 8), 8 data bytes.
 * State persists across the records of one input only. Each input starts from the same state:
 * fsd_state_init() for FSDState, fsd_rs_reset_all() for the handler's own statics (build.sh
 * registers them in the copy of fsd_handler.c it compiles; mayhem/harnesses/fsd_resettable.h):
 * nag_prng_state, nag_torq_walk, nag_exc_frames, nag_frames_until_exc, and in nag_faithful_modec
 * prev_das, s1_enter_ms, s2_enter_ms, strong_enter_ms, last_raw, last_level, s2_hold_until_ms,
 * s2_hold_raw, s2_hold_level, s2_level2_active, mild_walk.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fsd_handler.h"
#include "fsd_capture.h"
#include "fsd_fuzz_state.h"
#include "fsd_resettable.h"

static volatile uint8_t g_sink;

static void send_can_frame(const CANFRAME* f) {
    uint8_t x = (uint8_t)f->canId;
    for(uint8_t i = 0; i < f->data_lenght && i < MAX_LEN; i++) x ^= f->buffer[i];
    g_sink = x;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if(size < FSD_FUZZ_CFG_LEN) return -1;
    FSDState state;
    fsd_rs_reset_all();
    TeslaHWVersion hw = (TeslaHWVersion)(data[0] & 0x03u);
    fsd_state_init(&state, hw);
    fsd_fuzz_configure(&state, data);
    state.gtw_shield_armed = false; /* armed by fsd_handle_gtw_shield itself */
    bool shield_enabled = (data[0] & 0x20u) != 0;
    uint32_t now = 1000;
    data += FSD_FUZZ_CFG_LEN;
    size -= FSD_FUZZ_CFG_LEN;

    while(size >= FSD_FUZZ_REC_LEN) {
        CANFRAME frame;
        memset(&frame, 0, sizeof(frame));
        frame.canId = (uint32_t)data[0] | ((uint32_t)data[1] << 8);
        /* MCP2515 RXBnDLC: low nibble, clamped to 8 (mcp_can_2515.c). */
        frame.data_lenght = data[3] & 0x0Fu;
        if(frame.data_lenght > 8) frame.data_lenght = 8;
        memcpy(frame.buffer, data + 4, MAX_LEN);
        now += (uint32_t)(data[2] >> 2) * 8u;
        data += FSD_FUZZ_REC_LEN;
        size -= FSD_FUZZ_REC_LEN;

        if(state.das_ap_state < DAS_APSTATE_ENGAGED) {
            state.ap_unstable_tick_ms = now;
            state.soft_engage_latched = false;
            state.ap_inject_count = 0;
        }
        fsd_abort_guard_update(&state);

        state.rx_count++;
        char cap_line[48];
        (void)tesla_format_candump_line(cap_line, sizeof(cap_line), now, "can0",
                                        frame.canId, frame.buffer, frame.data_lenght);

        bool tx_allowed = fsd_can_transmit(&state);

        if(state.hw_version == TeslaHW_Legacy && frame.canId == CAN_ID_AP_CONTROL) {
            state.hw_version = TeslaHW_HW3;
            state.speed_profile = 2;
        }

        if(frame.canId == CAN_ID_GTW_CAR_STATE) {
            fsd_handle_gtw_car_state(&state, &frame);
        } else if(frame.canId == CAN_ID_BMS_HV_BUS) {
            fsd_handle_bms_hv(&state, &frame);
        } else if(frame.canId == CAN_ID_BMS_SOC) {
            fsd_handle_bms_soc(&state, &frame);
        } else if(frame.canId == CAN_ID_BMS_THERMAL) {
            fsd_handle_bms_thermal(&state, &frame, now);
        } else if(frame.canId == CAN_ID_DI_SYS_STATUS) {
            fsd_handle_di_system_status(&state, &frame);
        } else if(frame.canId == CAN_ID_VCRIGHT_STATUS) {
            fsd_handle_vcright_status(&state, &frame);
        } else if(frame.canId == CAN_ID_DI_SPEED) {
            fsd_handle_di_speed(&state, &frame);
            state.last_speed_tick_ms = now;
        } else if(frame.canId == CAN_ID_ESP_STATUS) {
            fsd_handle_esp_status(&state, &frame);
        } else if(frame.canId == CAN_ID_DAS_STATUS) {
            fsd_handle_das_status_hw4(&state, &frame);
        } else if(frame.canId == CAN_ID_DAS_STATUS2) {
            fsd_handle_das_status2(&state, &frame);
        } else if(frame.canId == CAN_ID_DAS_SETTINGS) {
            fsd_handle_das_settings(&state, &frame);
        } else if(frame.canId == CAN_ID_DAS_AP_CONFIG) {
            if(fsd_handle_tlssc_restore(&state, &frame) && tx_allowed) send_can_frame(&frame);
        } else if(frame.canId == CAN_ID_GTW_CONFIG_ETH) {
            fsd_handle_gtw_autopilot_tier(&state, &frame);
            if(shield_enabled) {
                if(fsd_handle_gtw_shield(&state, &frame) && tx_allowed) send_can_frame(&frame);
            } else if(fsd_handle_gtw_tier_override(&state, &frame) && tx_allowed) {
                send_can_frame(&frame);
            }
        }

        if(frame.canId == CAN_ID_TRACK_MODE_SET) {
            if(fsd_handle_track_mode_inject(&state, &frame) && tx_allowed) send_can_frame(&frame);
        } else if(frame.canId == CAN_ID_DAS_CONTROL) {
            fsd_handle_das_control(&state, &frame);
        } else if(frame.canId == CAN_ID_DI_STATE) {
            fsd_handle_di_state(&state, &frame);
        } else if(frame.canId == CAN_ID_DI_TORQUE) {
            fsd_handle_di_torque(&state, &frame);
        } else if(frame.canId == CAN_ID_UI_WARNING) {
            fsd_handle_ui_warning(&state, &frame);
        } else if(frame.canId == CAN_ID_STEER_ANGLE) {
            fsd_handle_steering_angle(&state, &frame, now);
        } else if(frame.canId == CAN_ID_DAS_STEER) {
            fsd_handle_das_steering(&state, &frame);
        }

        if(frame.canId == CAN_ID_VCFRONT_LIGHT) {
            if(fsd_handle_hazard_inject(&state, &frame) && tx_allowed) send_can_frame(&frame);
            if(fsd_handle_wiper_off(&state, &frame) && tx_allowed) send_can_frame(&frame);
        }

        if(frame.canId == CAN_ID_EPAS_STATUS) {
            fsd_handle_epas_steering_mode(&state, &frame);
            if(state.nag_killer) {
                CANFRAME echo;
                memset(&echo, 0, sizeof(echo));
                if(fsd_handle_nag_killer(&state, &frame, &echo, now) && tx_allowed) send_can_frame(&echo);
            }
        } else if(frame.canId == CAN_ID_STW_ACTN_RQ && state.hw_version == TeslaHW_Legacy) {
            fsd_handle_legacy_stalk(&state, &frame);
        } else if(frame.canId == CAN_ID_AP_LEGACY && state.hw_version == TeslaHW_Legacy) {
            if(fsd_handle_legacy_autopilot(&state, &frame, now) && tx_allowed) send_can_frame(&frame);
        } else if(frame.canId == CAN_ID_ISA_SPEED) {
            if(state.hw_version == TeslaHW_HW4) {
                if(!state.das_hw4_status_seen) fsd_handle_das_handsonly_399(&state, &frame);
                if(state.suppress_speed_chime && fsd_handle_isa_speed_chime(&frame) && tx_allowed)
                    send_can_frame(&frame);
            } else {
                fsd_handle_das_status_hw3(&state, &frame);
            }
        } else if(frame.canId == CAN_ID_FOLLOW_DIST) {
            fsd_handle_follow_distance(&state, &frame);
            if(fsd_handle_driver_assist_override(&state, &frame) && tx_allowed) send_can_frame(&frame);
        } else if(frame.canId == CAN_ID_AP_CONTROL) {
            if(fsd_handle_autopilot_frame(&state, &frame, now) && tx_allowed) send_can_frame(&frame);
        } else if(frame.canId == CAN_ID_VCLEFT_SWITCH) {
            if(fsd_handle_scroll_press_inject(&state, &frame, now) && tx_allowed) send_can_frame(&frame);
        }

        fsd_apply_signal_config(&state, &frame, now);
        fsd_autopark_update(&state, now);
    }
    return 0;
}
