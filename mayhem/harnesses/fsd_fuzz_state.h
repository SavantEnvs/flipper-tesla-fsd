/*
 * fsd_fuzz_state.h — shared by the two CAN-RX harnesses (C and C++).
 *
 * Both firmwares start from fsd_state_init(hw) and then copy the owner's
 * settings (Flipper: app->*, scenes/fsd_running.c; ESP32: NVS via prefs.cpp /
 * the dashboard) onto FSDState. The settings are not attacker data but they
 * decide which rewrite paths run, so the first FSD_FUZZ_CFG_LEN input bytes
 * pick them; every setting here is one the owner can toggle in the UI.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "fsd_state.h"

#define FSD_FUZZ_CFG_LEN 16
#define FSD_FUZZ_REC_LEN 12   /* id lo, id hi, flags, dlc, data[8] */

static inline void fsd_fuzz_set_bools(FSDState *s, const uint8_t *bits) {
    bool *fields[] = {
        &s->fsd_enabled, &s->nag_suppressed, &s->force_fsd, &s->fsd_unlock,
        &s->suppress_speed_chime, &s->emergency_vehicle_detect, &s->nag_killer,
        &s->nag_burst, &s->nag_epas_faithful, &s->continuous_ap, &s->precondition,
        &s->track_mode_inject, &s->track_post_cooling, &s->track_cmp_overclock,
        &s->ap_first, &s->ap_first_edge, &s->ap_first_minimal, &s->soft_engage,
        &s->abort_guard, &s->scroll_press_ap, &s->enhanced_autopilot,
        &s->summon_unlock, &s->speed_profile_locked, &s->hw3_speed_override,
        &s->tlssc_restore, &s->gtw_tier_override, &s->assist_nav_enable,
        &s->assist_hands_off, &s->assist_dev_mode, &s->assist_lhd_override,
        &s->assist_rhd_override, &s->assist_show_lane_graph, &s->assist_tlssc_bit38,
        &s->continue_on_green, &s->assist_telemetry_off, &s->cp_type_eu_rewrite,
        &s->extra_hazard_lights, &s->extra_wiper_off, &s->extra_park_inject,
        &s->extra_highbeam_strobe, &s->extra_turn_left, &s->extra_turn_right,
        &s->extra_wiper_wash, &s->ignore_ota, &s->china_mode,
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        *fields[i] = (bits[i / 8] >> (i % 8)) & 1u;
}

/* cfg: FSD_FUZZ_CFG_LEN bytes. Returns the hardware version chosen. */
static inline void fsd_fuzz_configure(FSDState *s, const uint8_t *cfg) {
    s->op_mode = (OpMode)((cfg[0] >> 2) % 3u);
    fsd_fuzz_set_bools(s, cfg + 1);             /* cfg[1..6] */
    s->accel_mode = cfg[7] & 0x03u;
    s->hw4_offset = cfg[8];
    s->track_rotation_pct = (uint8_t)(cfg[9] % 101u);
    s->track_stability_pct = (uint8_t)(cfg[10] % 101u);
    s->speed_profile = cfg[11] % 5u;
    s->apmv3_branch = cfg[12];
    /* Signal Map (#100/#122): user-configured DAS / steering frame layout.
     * Byte positions and shifts are 0-7, what the dashboard's sig_cfg accepts. */
    if (cfg[13] & 0x01u) {
        static const uint16_t das_ids[] = {0x399u, 0x39Bu, 0x389u, 0x3FDu};
        s->cfg_das_id = das_ids[(cfg[13] >> 1) & 3u];
        s->cfg_apstate_byte = (uint8_t)(cfg[14] & 0x07u);
        s->cfg_apstate_shift = (uint8_t)((cfg[14] >> 4) & 0x07u);
        s->cfg_apstate_mask = 0x0Fu;
        s->cfg_handson_byte = (uint8_t)(cfg[15] & 0x07u);
        s->cfg_handson_shift = (uint8_t)((cfg[15] >> 4) & 0x07u);
        s->cfg_handson_mask = (cfg[13] & 0x08u) ? 0x0Fu : 0u;
    }
    if (cfg[13] & 0x10u) {
        s->cfg_steer_id = (cfg[13] & 0x20u) ? 0x129u : 0x370u;
        s->cfg_steer_hi = (uint8_t)((cfg[13] >> 6) & 0x03u);
        s->cfg_steer_lo = (uint8_t)(cfg[14] & 0x07u);
    }
}
