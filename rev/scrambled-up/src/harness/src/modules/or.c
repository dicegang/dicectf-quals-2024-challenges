#include <stddef.h>
#include <stdint.h>

#include "interface.h"

struct module_args or (struct module_args args, struct module_env env) {
    uint64_t ret = 0;
    for (size_t i = 0; i < args.num_args; ++i) {
        ret |= args.args[i].integer;
    }

    return (struct module_args){
        .num_args = 1,
        .args = {
            [0] = create_value_integer(ret),
        },
    };
}
