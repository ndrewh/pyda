
#ifndef NDEBUG
#define DEBUG_PRINTF(...) dr_fprintf(STDERR, __VA_ARGS__)
#else
#define DEBUG_PRINTF(...)
#endif