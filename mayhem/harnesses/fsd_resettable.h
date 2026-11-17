/*
 * fsd_resettable.h — force-included (-include) into the build-time copies of the two
 * fsd_handler sources that mayhem/build.sh generates (mayhem/out/gen/).
 *
 * The handlers keep protocol state in file- and function-scope statics that
 * fsd_state_init() cannot reach: the nag-killer PRNG and torque walk, the EPAS-faithful
 * (Mode-C) tracker, and the ESP32 gear-lever tracker. build.sh rewrites each
 * "static T name = init;" in the copy to FSD_RS_G / FSD_RS_L, which declares the same static and
 * records its address and initial value. fsd_rs_reset_all() puts every registered one back,
 * so an input's result depends on that input alone (docs/rules/common.md).
 * Upstream's own sources are not touched.
 */
#pragma once
#include <stddef.h>
#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif
void fsd_rs_add(void *p, const void *init, size_t n);
void fsd_rs_reset_all(void);
#ifdef __cplusplus
}
#endif

/* File scope: registered by a constructor, before main(). */
#define FSD_RS_G(T, N, INIT)                                  \
    static T N = INIT;                                        \
    __attribute__((constructor)) static void N##_rs_reg(void) { \
        T init_ = INIT;                                       \
        fsd_rs_add(&N, &init_, sizeof init_);                 \
    }

/* Function scope: registered the first time the declaration is reached, before the function can
 * change it; a function that has not run yet still holds its initial value. */
#define FSD_RS_L(T, N, INIT)                                  \
    static T N = INIT;                                        \
    {                                                         \
        static bool N##_rs_done;                              \
        if (!N##_rs_done) {                                   \
            N##_rs_done = true;                               \
            T N##_rs_init = INIT;                             \
            fsd_rs_add(&N, &N##_rs_init, sizeof N##_rs_init); \
        }                                                     \
    }
