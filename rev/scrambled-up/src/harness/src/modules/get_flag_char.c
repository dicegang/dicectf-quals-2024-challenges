#include <stddef.h>
#include <stdint.h>

#include "interface.h"

struct module_args get_flag_char(struct module_args args, struct module_env env) {
    struct module_args ret = {
        .num_args = 1,
        .args = {
            [0] = create_value_integer(args.args[0].integer >= env.flag.length ? 0 : env.flag.data[args.args[0].integer]),
        },
    };

    return ret;
}
