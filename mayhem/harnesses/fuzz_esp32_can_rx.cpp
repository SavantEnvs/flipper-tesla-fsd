/*
 * fuzz_esp32_can_rx.cpp — ESP32 firmware CAN receive path.
 *
 * Feeds a stream of CAN frames, as they come off the TWAI / MCP2515 /
 * MCP2518FD drivers, through the protocol handlers of
 * esp32/.firmware/fsd_handler.cpp in the order process_frame()
 * (esp32/.firmware/main.cpp) calls them. process_frame() itself lives in the
 * Arduino/FreeRTOS translation unit and cannot be built on the host, so its
 * dispatch is mirrored here, guards included (tesla_can_rx_accept, the dlc==0
 * drop, the hardware-version checks). Logging, blackbox, capture and the actual
 * bus sends are left out: they do not change FSDState.
 *
 * Input: FSD_FUZZ_CFG_LEN config bytes (hardware version, op mode, the owner's
 * feature toggles — see fsd_fuzz_state.h), then records of FSD_FUZZ_REC_LEN:
 *   [0..1] 11/16-bit id (LE)   [2] flags: bit0 ext, bit1 remote, bits2-7 dt*8ms
 *   [3]    dlc as the driver reports it (0..255; >8 is what 44de077 drops)
 *   [4..11] data bytes
 * State persists across the records of one input only. Each input starts from the same state:
 * fsd_state_init() for FSDState, fsd_rs_reset_all() for the handler's own statics (build.sh
 * registers them in the copy of fsd_handler.cpp it compiles; mayhem/harnesses/fsd_resettable.h):
 * nag_prng_state, nag_torq_walk, nag_exc_frames, nag_frames_until_exc; in nag_faithful_modec
 * prev_das, s1_enter_ms, s2_enter_ms, strong_enter_ms, last_raw, last_level, s2_hold_until_ms,
 * s2_hold_raw, s2_hold_level, s2_level2_active, mild_walk; in fsd_handle_gear_lever active,
 * best_pos, last_seen_ms; and the two hw_fallback counters below.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fsd_handler.h"  // esp32/.firmware (first on the include path)
#include "can_signals.h"
#include "config.h"
#include "fsd_can_ops.h"
#include "fsd_events.h"
#include "fsd_freshness.h"
#include "fsd_fuzz_state.h"
#include "fsd_resettable.h"

static FSDState g_state;
static uint32_t g_now;

static uint32_t millis() { return g_now; }

static bool hw_uses_hw3_das_status(TeslaHWVersion hw) {
    return hw == TeslaHW_Legacy || hw == TeslaHW_HW3;
}
static bool hw_uses_hw4_das_status(TeslaHWVersion hw) { return hw == TeslaHW_HW4; }

static bool frame_looks_like_hw3_das_status(const CanFrame &frame) {
    if (frame.id != CAN_ID_DAS_STATUS_HW3 || frame.dlc != CAN_FRAME_MAX_DATA_LEN) return false;
    uint8_t ap_state = frame.data[SIG_DAS_HW3_AP_STATE_BYTE] & SIG_DAS_HW3_AP_STATE_MASK;
    uint8_t hands_on = (frame.data[SIG_DAS_HANDS_ON_STATE_BYTE] >> SIG_DAS_HANDS_ON_STATE_SHIFT) &
                       SIG_DAS_HANDS_ON_STATE_MASK;
    return ap_state <= SIG_DAS_HW3_AP_ACTIVE_STATE && hands_on <= SIG_DAS_HANDS_ON_SUSPENDED;
}

static void apply_detected_hw(TeslaHWVersion hw) {
    if (hw == TeslaHW_Unknown) return;
    if (g_state.hw_override != TeslaHW_Unknown) return;
    if (g_state.hw_version == hw) return;
    fsd_apply_hw_version(&g_state, hw);
}

static uint32_t hw_fallback_3fd_count, hw_fallback_399_count;
static volatile uint8_t g_sink;

static void send_on_bus(const CanFrame &f) {
    // The frame the firmware would transmit: touch every byte it would copy out.
    uint8_t x = (uint8_t)f.id;
    for (uint8_t i = 0; i < f.dlc && i < MAX_LEN; i++) x ^= f.data[i];
    g_sink = x;
}

static void process_frame(const CanFrame &frame) {
    uint32_t now = millis();
    bool fresh = fsd_tx_fresh(frame.rx_ms, now);
    bool usable = tesla_can_rx_accept(frame.id, frame.ext != 0u, frame.req != 0u, frame.dlc);
    g_state.rx_count++;
    if (usable) fsd_apply_signal_config(&g_state, &frame, millis());
    bool das_cfg = (g_state.cfg_das_id != 0);
    bool steer_cfg = (g_state.cfg_steer_id != 0);
    if (g_state.das_ap_state < DAS_APSTATE_ENGAGED) {
        g_state.ap_unstable_tick_ms = millis();
        g_state.soft_engage_latched = false;
        g_state.ap_inject_count = 0;
    }
    fsd_abort_guard_update(&g_state);
    fsd_autopark_update(&g_state, now);
    (void)fsd_events_poll(&g_state, now);

    if (!usable) return;
    if (frame.dlc == 0) return;

    if (frame.id == CAN_ID_GTW_CAR_CONFIG) {
        TeslaHWVersion hw = fsd_detect_hw_version(&frame);
        if (hw != TeslaHW_Unknown && g_state.hw_version == TeslaHW_Unknown) apply_detected_hw(hw);
        return;
    }
    if (frame.id == CAN_ID_GTW_CAR_STATE) { fsd_handle_gtw_car_state(&g_state, &frame); return; }
    if (frame.id == CAN_ID_BMS_HV_BUS) { fsd_handle_bms_hv(&g_state, &frame); return; }
    if (frame.id == CAN_ID_BMS_SOC) { fsd_handle_bms_soc(&g_state, &frame); return; }
    if (frame.id == CAN_ID_UI_RANGE) { fsd_handle_ui_range(&g_state, &frame); return; }
    if (frame.id == CAN_ID_BMS_THERMAL) { fsd_handle_bms_thermal(&g_state, &frame, now); return; }

    if (!das_cfg && hw_uses_hw3_das_status(g_state.hw_version) && frame.id == CAN_ID_DAS_STATUS_HW3) {
        fsd_handle_das_status_hw3(&g_state, &frame);
        return;
    }
    if (!das_cfg && hw_uses_hw4_das_status(g_state.hw_version) && frame.id == CAN_ID_DAS_STATUS_HW4) {
        fsd_handle_das_status_hw4(&g_state, &frame);
        return;
    }
    if (!das_cfg && hw_uses_hw4_das_status(g_state.hw_version) && frame.id == CAN_ID_DAS_STATUS_HW3 &&
        !g_state.das_hw4_status_seen) {
        fsd_handle_das_handsonly_399(&g_state, &frame);
    }

    if (frame.id == CAN_ID_SCCM_RSTALK) {
        if (frame.dlc > SIG_GEAR_LEVER_POS_BYTE) {
            uint8_t detent = (frame.data[SIG_GEAR_LEVER_POS_BYTE] >> SIG_GEAR_LEVER_POS_SHIFT) &
                             SIG_GEAR_LEVER_POS_MASK;
            if (detent == SIG_GEAR_LEVER_FULL_DOWN) g_state.summon_unlock = false;
        }
        if (g_state.hw_version != TeslaHW_HW3 && g_state.hw_version != TeslaHW_Legacy) return;
        fsd_handle_gear_lever(&g_state, &frame, millis());
        return;
    }
    if (frame.id == CAN_ID_UI_MAP_DATA) { fsd_handle_ui_map_data(&g_state, &frame, millis()); return; }
    if (frame.id == CAN_ID_DAS_STATUS2) { fsd_handle_das_status2(&g_state, &frame, millis()); return; }
    if (frame.id == CAN_ID_DAS_CONTROL) { fsd_handle_das_control(&g_state, &frame); return; }
    if (frame.id == CAN_ID_DI_SPEED) {
        uint32_t now_ms = millis();
        fsd_handle_di_speed(&g_state, &frame);
        g_state.last_speed_tick_ms = now_ms;
        fsd_perf_on_speed(&g_state, now_ms);
        if (g_state.summon_unlock && g_state.vehicle_speed_kph <= FSD_DI_SPEED_MAX_VALID_KPH &&
            g_state.vehicle_speed_kph > SUMMON_DISABLE_SPEED_KPH)
            g_state.summon_unlock = false;
        return;
    }
    if (frame.id == CAN_ID_DI_SYS_STATUS) { fsd_handle_di_gear(&g_state, &frame, millis()); return; }
    if (frame.id == CAN_ID_VCFRONT_LIGHT) { fsd_handle_vcfront_lighting(&g_state, &frame); return; }
    if (frame.id == CAN_ID_ESP_STATUS) { fsd_handle_esp_status(&g_state, &frame); return; }
    if (frame.id == CAN_ID_ESP_WHEELSPD) { fsd_handle_wheel_speeds(&g_state, &frame); return; }
    if (frame.id == CAN_ID_VCSEC_TPMS) { fsd_tpms_update(&g_state.tpms, frame.data, frame.dlc, now); return; }
    if (!steer_cfg && frame.id == CAN_ID_STEER_ANGLE) {
        fsd_handle_steering_angle(&g_state, &frame, now);
        return;
    }
    if (frame.id == CAN_ID_CP_STATUS) {
        CanFrame f = frame;
        bool modified = fsd_handle_cp_type_rewrite(&g_state, &f, now);
        if (modified && fsd_can_transmit(&g_state) && fresh) {
            send_on_bus(f);
            g_state.cp_type_tx_count++;
        }
        return;
    }

    bool tx = fsd_can_transmit(&g_state);
    bool ap_ok = fsd_ap_first_allows(&g_state, millis()) && fsd_soft_engage_allows(&g_state, millis()) &&
                 fsd_abort_guard_allows(&g_state);

    if (frame.id == CAN_ID_EPAS_STATUS) {
        CanFrame echo = {};
        fsd_handle_epas_status(&g_state, &frame);
        bool fired = (tx && ap_ok && fresh) ? fsd_handle_nag_killer(&g_state, &frame, &echo, millis()) : false;
        if (fired) send_on_bus(echo);
        return;
    }
    if (frame.id == CAN_ID_STW_ACTN_RQ && g_state.hw_version == TeslaHW_Legacy) {
        fsd_handle_legacy_stalk(&g_state, &frame);
        return;
    }
    if (frame.id == CAN_ID_AP_LEGACY && g_state.hw_version == TeslaHW_Legacy) {
        CanFrame f = frame;
        bool minimal_ok = !(g_state.ap_first_minimal && g_state.ap_inject_count >= AP_MINIMAL_INJECT_FRAMES);
        bool modified = minimal_ok && fsd_handle_legacy_autopilot(&g_state, &f);
        if (modified && ap_ok && fresh && g_state.ap_first_minimal) g_state.ap_inject_count++;
        if (modified && tx && ap_ok && fresh) send_on_bus(f);
        return;
    }
    if (g_state.hw_version == TeslaHW_Legacy && frame.id == CAN_ID_AP_CONTROL) apply_detected_hw(TeslaHW_HW3);

    if (g_state.hw_version == TeslaHW_Unknown) {
        if (frame.id == CAN_ID_AP_LEGACY) {
            apply_detected_hw(TeslaHW_Legacy);
        } else if (frame.id == CAN_ID_DAS_STATUS_HW4 && frame.dlc == CAN_FRAME_MAX_DATA_LEN) {
            apply_detected_hw(TeslaHW_HW4);
            hw_fallback_3fd_count = 0;
            hw_fallback_399_count = 0;
        } else if (frame_looks_like_hw3_das_status(frame)) {
            if (++hw_fallback_399_count >= 2u) apply_detected_hw(TeslaHW_HW3);
        } else if (frame.id == CAN_ID_AP_CONTROL) {
            if (++hw_fallback_3fd_count >= 10u) apply_detected_hw(TeslaHW_HW3);
        }
    }

    if (frame.id == CAN_ID_ISA_SPEED && g_state.hw_version == TeslaHW_HW4 && g_state.suppress_speed_chime) {
        CanFrame f = frame;
        if (fsd_handle_isa_speed_chime(&f) && tx && fresh) send_on_bus(f);
        return;
    }
    if (frame.id == CAN_ID_FOLLOW_DIST) {
        CanFrame f = frame;
        fsd_handle_follow_distance(&g_state, &frame);
        if (fsd_handle_driver_assist_override(&g_state, &f) && tx && fresh) send_on_bus(f);
        return;
    }
    if (frame.id == CAN_ID_DAS_AP_CONFIG) {
        CanFrame f = frame;
        if (fsd_handle_tlssc_restore(&g_state, &f) && tx && fresh) send_on_bus(f);
        return;
    }
    if (frame.id == CAN_ID_TRACK_MODE_SET) {
        CanFrame f = frame;
        if (fsd_handle_track_mode_inject(&g_state, &f) && tx && fresh) send_on_bus(f);
        return;
    }
    if (frame.id == CAN_ID_UI_POWERTRAIN) {
        CanFrame f = frame;
        if (fsd_handle_accel_mode(&g_state, &f, millis()) && tx && fresh) send_on_bus(f);
        (void)fsd_accel_sent_map(&g_state);
        return;
    }
    if (frame.id == CAN_ID_AP_CONTROL) {
        CanFrame f = frame;
        bool minimal_ok = !(g_state.ap_first_minimal && g_state.ap_inject_count >= AP_MINIMAL_INJECT_FRAMES);
        bool modified = minimal_ok && fsd_handle_autopilot_frame(&g_state, &f);
        if (modified && ap_ok && fresh && g_state.ap_first_minimal) g_state.ap_inject_count++;
        if (modified && tx && ap_ok && fresh) send_on_bus(f);
        return;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < FSD_FUZZ_CFG_LEN) return -1;
    g_now = 1000;
    hw_fallback_3fd_count = hw_fallback_399_count = 0;
    fsd_rs_reset_all();
    TeslaHWVersion hw = (TeslaHWVersion)(data[0] & 0x03u);
    fsd_state_init(&g_state, hw);
    fsd_fuzz_configure(&g_state, data);
    // hw_override: the owner pinned the version (bit 4) — detection must not move it.
    if (data[0] & 0x10u) g_state.hw_override = hw;
    data += FSD_FUZZ_CFG_LEN;
    size -= FSD_FUZZ_CFG_LEN;

    while (size >= FSD_FUZZ_REC_LEN) {
        CanFrame f;
        memset(&f, 0, sizeof(f));
        f.id = (uint32_t)data[0] | ((uint32_t)data[1] << 8);
        f.ext = data[2] & 0x01u;
        f.req = (data[2] >> 1) & 0x01u;
        f.dlc = data[3];
        memcpy(f.data, data + 4, MAX_LEN);
        g_now += (uint32_t)(data[2] >> 2) * 8u;
        f.rx_ms = g_now;
        process_frame(f);
        data += FSD_FUZZ_REC_LEN;
        size -= FSD_FUZZ_REC_LEN;
    }
    return 0;
}
