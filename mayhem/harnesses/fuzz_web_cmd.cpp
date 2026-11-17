/*
 * fuzz_web_cmd.cpp — ESP32 dashboard command parser (esp32/.firmware/web_cmd.h).
 *
 * The dashboard takes WebSocket frames and POST bodies from any client on the
 * AP / station network. web_dashboard.cpp (Arduino-only) refuses anything over
 * WEB_CMD_MAX_LEN (767 bytes) and hands the rest, NOT NUL-terminated, to
 * web_cmd_parse(); each command then reads its value with one of the WebCmd
 * accessors, and wifi_cfg runs web_wifi_parse(). This harness does the same
 * with an exact-size heap copy, so an over-read past the frame is caught.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "web_cmd.h"

#define WEB_CMD_MAX_LEN 767u   /* web_dashboard.cpp */

static volatile unsigned g_sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > WEB_CMD_MAX_LEN) return -1;   // the dashboard answers too_long first
    char *buf = (char *)malloc(size ? size : 1);
    if (size) memcpy(buf, data, size);

    WebCmd cmd;
    if (web_cmd_parse(buf, size, &cmd)) {
        int n = 0;
        bool b = false;
        char csv[128], name[40], small[8];
        g_sink += (unsigned)(cmd.is("wifi_cfg"));
        g_sink += (unsigned)(cmd.boolean(&b) ? b : 0);
        g_sink += (unsigned)(cmd.integer(&n) ? n : 0);
        g_sink += (unsigned)(cmd.integer_capped(&n, 0, 100) ? n : 0);
        g_sink += (unsigned)(cmd.integer_capped(&n, 10000, INT32_MAX) ? n : 0);
        if (cmd.string(csv, sizeof(csv))) g_sink += (unsigned)((int)strlen(csv));
        if (cmd.string(name, sizeof(name))) g_sink += (unsigned)((int)strlen(name));
        if (cmd.string(small, sizeof(small))) g_sink += (unsigned)((int)strlen(small));

        WebWifiCfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cmd.field = web_wifi_parse(cmd.value, &cfg);
        if (!cmd.field) {
            g_sink += (int)strlen(cfg.ssid) + (int)strlen(cfg.pass) + (int)strlen(cfg.sta_ssid) +
                      (int)strlen(cfg.sta_pass) + (int)strlen(cfg.host);
            if (cfg.has_host && cfg.host[0]) g_sink += (unsigned)(web_hostname_valid(cfg.host));
        }
        const char *err = web_cmd_error(cmd.bad_value ? WEB_CMD_BAD_VALUE : WEB_CMD_OK);
        if (err) g_sink += (unsigned)(err[0]);
    }
    free(buf);
    return 0;
}
