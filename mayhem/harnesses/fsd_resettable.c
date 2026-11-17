/* The registry behind fsd_resettable.h. */
#include <stdlib.h>
#include <string.h>

#include "fsd_resettable.h"

#define FSD_RS_MAX 64
#define FSD_RS_MAX_SIZE 8

static struct {
    void *p;
    size_t n;
    unsigned char init[FSD_RS_MAX_SIZE];
} g_rs[FSD_RS_MAX];
static size_t g_rs_count;

void fsd_rs_add(void *p, const void *init, size_t n) {
    if (g_rs_count >= FSD_RS_MAX || n > FSD_RS_MAX_SIZE) abort();
    g_rs[g_rs_count].p = p;
    g_rs[g_rs_count].n = n;
    memcpy(g_rs[g_rs_count].init, init, n);
    g_rs_count++;
}

void fsd_rs_reset_all(void) {
    for (size_t i = 0; i < g_rs_count; i++) memcpy(g_rs[i].p, g_rs[i].init, g_rs[i].n);
}
