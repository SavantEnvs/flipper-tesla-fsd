/*
 * fuzz_captive_probe.cpp — captive-portal request classification
 * (esp32/.firmware/captive_probe.h). On the SoftAP every client's request
 * path, User-Agent and Host header end up here, together with a per-client
 * table keyed by source address that lives for the whole boot.
 *
 * Input: a sequence of requests, each
 *   [0..3] source IPv4 (LE)  [4] flags: bit0 portal active, bit1 the request
 *   loaded the dashboard (CaptiveClients::note), bit2 an AP address is set
 *   then "path\0ua\0host\0" (a truncated tail is the last request).
 * The client table is per input.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <string>

#include "captive_probe.h"

static volatile unsigned g_sink;

static std::string take(const uint8_t *&p, const uint8_t *end) {
    const uint8_t *z = (const uint8_t *)memchr(p, '\0', (size_t)(end - p));
    std::string s((const char *)p, z ? (size_t)(z - p) : (size_t)(end - p));
    p = z ? z + 1 : end;
    return s;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    CaptiveClients clients;
    const uint8_t *p = data, *end = data + size;
    while (end - p >= 5) {
        uint32_t ip = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        uint8_t flags = p[4];
        p += 5;
        std::string path = take(p, end), ua = take(p, end), host = take(p, end);
        bool active = flags & 1;
        const char *ap_ip = (flags & 4) ? "192.168.4.1" : "";
        const char *hostp = (flags & 8) ? nullptr : host.c_str();
        const char *uap = (flags & 16) ? nullptr : ua.c_str();

        if (flags & 2) clients.note(active, ip, uap);
        g_sink += (unsigned)(captive_is_apple_probe(path.c_str(), uap));
        g_sink += (unsigned)((int)captive_probe_reply(clients, ip, path.c_str(), uap));
        g_sink += (unsigned)(captive_host_is_ours(hostp, ap_ip));
        g_sink += (unsigned)((int)captive_not_found_reply(clients, active, ip, path.c_str(), uap, hostp, ap_ip));
    }
    return 0;
}
