
#ifndef NDEBUG
#define DEBUG_PRINTF(...) { \
    dr_fprintf(STDERR, __VA_ARGS__); \
    dr_flush_file(STDERR); \
}
#else
#define DEBUG_PRINTF(...)
#endif