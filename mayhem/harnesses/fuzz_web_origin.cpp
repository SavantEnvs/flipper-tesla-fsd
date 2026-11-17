/*
 * fuzz_web_origin.cpp — Origin / Host header checks (esp32/.firmware/web_origin.h):
 * the CSRF and DNS-rebinding gate in front of the dashboard WebSocket, its POST
 * endpoints and the :82 CAN stream. Both headers are attacker-supplied.
 *
 * Input: byte 0 picks which of the device's own names are set (as
 * test/test_web_origin.cpp does: AP address, station address, hostname), the
 * rest is "<Origin>\n<Host>" (each a C string, as the web server hands it over;
 * a missing part is a header that was not sent).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "web_origin.h"

static volatile unsigned g_sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return -1;
    uint8_t sel = data[0];
    data++;
    size--;

    char *buf = (char *)malloc(size + 1);
    memcpy(buf, data, size);
    buf[size] = '\0';
    char *origin = buf;
    char *host = nullptr;
    char *nl = (char *)memchr(buf, '\n', size);
    if (nl) {
        *nl = '\0';
        host = nl + 1;
    }
    if (sel & 0x08) origin = nullptr;   // no Origin header

    WebOwnNames own;
    own.ap_ip = (sel & 1) ? "192.168.4.1" : "";
    own.sta_ip = (sel & 2) ? "10.0.0.42" : ((sel & 0x10) ? "0.0.0.0" : nullptr);
    own.hostname = (sel & 4) ? "tesla-fsd" : nullptr;

    g_sink += (unsigned)(web_ws_origin_ok(origin, own));
    g_sink += (unsigned)(web_post_origin_ok(origin, own));
    g_sink += (unsigned)(web_host_header_ours(host, own, ":80"));
    g_sink += (unsigned)(web_host_header_ours(host, own, ":82"));
    g_sink += (unsigned)(web_origin_ours(origin, own));
    g_sink += (unsigned)((int)web_stream_access(origin, host, own));
    free(buf);
    return 0;
}
