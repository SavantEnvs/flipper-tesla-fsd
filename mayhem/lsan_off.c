/* Leaks are not the bug class this integration fuzzes for: turn LeakSanitizer off at build time
 * (ASan and UBSan stay fully on). Linked into every fuzzer and -standalone binary. */
int __lsan_is_turned_off(void) { return 1; }
