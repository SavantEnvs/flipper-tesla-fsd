/*
 * fuzz_cantest_profile.c — .cantest test-profile loader (fsd_logic/fsd_profile.c).
 *
 * A .cantest file is user-authored text from the SD card (docs/cantest-format.md,
 * examples/example.cantest). scenes/main_menu.c reads at most 4095 bytes into a
 * NUL-terminated buffer, splits it on '\n' and runs fsd_profile_parse_line() on
 * each line, keeping up to FSD_SEND_MAX_STEPS steps; this harness does exactly
 * that (same buffer size, name buffer of 34, step cap), then asks the safety
 * interlock whether the loaded steps may go out.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fsd_handler.h"
#include "fsd_profile.h"

#define FSD_SEND_MAX_STEPS 48   /* tesla_fsd_app.h */

static volatile uint32_t g_sink;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char buf[4096];
    size_t n = size < sizeof(buf) - 1 ? size : sizeof(buf) - 1;
    memcpy(buf, data, n);
    buf[n] = '\0';

    FsdProfileStep steps[FSD_SEND_MAX_STEPS];
    unsigned step_count = 0, blocked = 0;
    char send_name[34] = {0};
    char* p = buf;
    while(*p && step_count < FSD_SEND_MAX_STEPS) {
        char* nl = strchr(p, '\n');
        if(nl) *nl = '\0';
        FsdProfileStep st;
        char nm[34];
        FsdProfileLineKind k = fsd_profile_parse_line(p, &st, nm, sizeof(nm));
        if(k == FSD_PLINE_STEP) {
            steps[step_count++] = st;
        } else if(k == FSD_PLINE_BLOCKED) {
            blocked++;
        } else if(k == FSD_PLINE_NAME) {
            strncpy(send_name, nm, sizeof(send_name) - 1);
            send_name[sizeof(send_name) - 1] = '\0';
        }
        if(!nl) break;
        p = nl + 1;
    }

    FSDState state;
    fsd_state_init(&state, TeslaHW_HW3);
    state.speed_seen = true;
    state.last_speed_tick_ms = 1000;
    for(unsigned i = 0; i < step_count; i++) {
        const FsdProfileStep* s = &steps[i];
        uint32_t x = s->can_id ^ s->repeat ^ s->delay_ms;
        for(uint8_t j = 0; j < s->dlc && j < MAX_LEN; j++) x ^= s->data[j];
        x ^= fsd_profile_id_blocked(s->can_id);
        x ^= fsd_profile_tx_allowed(&state, 1000u + s->delay_ms);
        g_sink += x;
    }
    g_sink += blocked + (uint32_t)strlen(send_name);
    return 0;
}
