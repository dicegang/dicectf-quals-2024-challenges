#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

#include "interface.h"

struct module_args pshufb(struct module_args args, struct module_env env) {
    uint8_t mapping[] = {15, 13, 7, 8, 5, 3, 6, 4, 14, 0, 2, 11, 9, 12, 10, 1};
    _Static_assert(sizeof(mapping) == 16);

    uint8_t real_selector[16];
    for (uint8_t i = 0; i < 16; ++i) {
        real_selector[i] = mapping[args.args[1].string.data[i] ^ 78];
    }

    __m128i source = _mm_loadu_si128((__m128i *) args.args[0].string.data);
    __m128i selector = _mm_loadu_si128(real_selector);

    __m128i result = _mm_shuffle_epi8(source, selector);

    uint8_t *result_out = env.malloc(16);
    _mm_storeu_si128((__m128i *) result_out, result);

    return (struct module_args){
        .num_args = 1,
        .args = {
            [0] = create_value_string(result_out, 16),
        },
    };
}
