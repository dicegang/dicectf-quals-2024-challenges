#pragma once
#include <stdio.h>
#include <stdlib.h>

#ifndef NDEBUG
#define ASSERT(x, ...)                                                              \
    do {                                                                            \
        if (!(!!(x))) {                                                             \
            printf("[%s:%d] Assertion failed '" #x "'\n", __FILE_NAME__, __LINE__); \
            __VA_OPT__(printf(__VA_ARGS__));                                        \
            abort();                                                                \
        }                                                                           \
    } while (0)
#define ISDEBUG
#define DEBUG(fmt, ...) \
    do { fprintf(stderr, "%s:%d (%s): " fmt "\n", __FILE_NAME__, __LINE__, __func__ __VA_OPT__(, ) __VA_ARGS__); } while (0)
#else
#define ASSERT(x, ...)
#define DEBUG(fmt, ...)
#endif

#define MAX(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })
#define MIN(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })