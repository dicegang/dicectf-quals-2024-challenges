#include <stddef.h>
#include <stdint.h>

#include "interface.h"

struct module_args not(struct module_args args, struct module_env env) {
    struct module_args ret = {
        .num_args = args.num_args,
    };

    for (size_t i = 0; i < args.num_args; ++i) {
        ret.args[i] = create_value_integer(args.args[i].integer ? 0 : 1);
    }

    return ret;
}
