#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../util.h"

enum value_kind {
    VALUE_EMPTY = 0,
    VALUE_STRING,
    VALUE_INTEGER,
};

struct value_string {
    uint8_t *data;
    size_t length;
};

struct value {
    enum value_kind kind;
    union {
        struct value_string string;
        uint64_t integer;
    };
};


#define create_value_integer(val) ((struct value){.kind = VALUE_INTEGER, .integer = val})
#define create_value_string(val, size) ((struct value){.kind = VALUE_STRING, .string = {.data = (val), .length = (size)}})

struct module_args {
    size_t num_args;
    struct value args[16];
};

struct module_env {
    void *(*malloc)(size_t size);
    void (*free)(void *);
#ifdef ISDEBUG
    int (*printf)(char const*, ...);
#endif
    struct value_string flag;
};