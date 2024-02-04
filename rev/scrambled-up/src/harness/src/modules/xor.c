#include <stddef.h>
#include <stdint.h>

#include "interface.h"

struct module_args xor (struct module_args args, struct module_env env) {
    if (args.args[0].kind == VALUE_INTEGER) {
        uint64_t ret = 0;
        for (size_t i = 0; i < args.num_args; ++i) {
            ret ^= args.args[i].integer;
        }

        return (struct module_args){
            .num_args = 1,
            .args = {
                [0] = create_value_integer(ret),
            }};
    }

    struct value_string arg0 = args.args[0].string;
    struct value_string arg1 = args.args[1].string;

    size_t len = MAX(arg0.length, arg1.length);

    struct value_string ret = {
        .length = len,
        .data = env.malloc(len),
    };

    for (size_t i = 0; i < len; ++i) {
        ret.data[i] = arg0.data[i] ^ arg1.data[i];
    }

    return (struct module_args){
        .num_args = 1,
        .args = {
            [0] = create_value_string(ret.data, len),
        },
    };
}
