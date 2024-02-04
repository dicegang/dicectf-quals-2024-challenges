#include <stddef.h>
#include <stdint.h>

#include "interface.h"

enum MAZE_OP {
    UR = 0,
    U,
    UL,
    L,
    R,
    DR,
    D,
    DL,

    SET = 10,
    REMOVE = 11,

    GET_RESULT = 12,
};


struct maze_state {
    uint32_t x;
    uint32_t y;

    bool failed;
    uint8_t maze[128][128];
};

struct module_args maze(struct module_args args, struct module_env env) {
    struct maze_state *ptr = (struct maze_state *) args.args[0].integer;

    if (ptr == NULL) {
        struct maze_state *p = env.malloc(sizeof(*p));
        p->x = 64;
        p->y = 64;
        return (struct module_args){
            .num_args = 1,
            .args = {
                [0] = create_value_integer((uint64_t) p),
            },
        };
    }

    uint64_t volatile op = args.args[1].integer;

    if (op == GET_RESULT) {
#ifdef ISDEBUG
        char c[] = {'R', 'E', 'T', '=', '%', 'z', 'u', '\n', 0};
        env.printf(c, ptr->failed ? 0 : ((ptr->x << 16) | ptr->y));
#endif

        return (struct module_args){
            .num_args = 1,
            .args = {
                [0] = create_value_integer(ptr->failed ? 0 : ((ptr->x << 16) | ptr->y)),
            }};
    }

    if (op == SET || op == REMOVE) {
        uint64_t x = args.args[2].integer;
        uint64_t y = args.args[3].integer;
        ptr->maze[x][y] = 0xff;

#ifdef ISDEBUG
        char c[] = {'S', 'E', 'T', '%', 'p', '=', '%', 'd', ',', '%', 'd', ',', '%', 'd', '\n', 0};
        env.printf(c, &ptr->maze[ptr->x][ptr->y], ptr->maze[x][y], (int) x, (int) y);
#endif

        return (struct module_args){
            .num_args = 1,
            .args = {
                [0] = create_value_integer((uint64_t) ptr),
            }};
    }

    if (op == UR) {
        ptr->x++;
        ptr->y++;
    }
    if (op == U) {
        ptr->y++;
    }
    if (op == UL) {
        ptr->x--;
        ptr->y++;
    }
    if (op == L) {
        ptr->x--;
    }
    if (op == R) {
        ptr->x++;
    }
    if (op == DR) {
        ptr->x++;
        ptr->y--;
    }
    if (op == D) {
        ptr->y--;
    }
    if (op == DL) {
        ptr->x--;
        ptr->y--;
    }

#ifdef ISDEBUG
    char c[] = {'O', 'P', '=', '%', 'd', ',', 'x', '=', '%', 'd', ',', 'y', '=', '%', 'd', '\n', 0};
    env.printf(c, op, (int) ptr->x, (int) ptr->y);
#endif

    if (ptr->maze[ptr->x][ptr->y]) {
#ifdef ISDEBUG
        char c[] = {'F', 'A', 'I', 'L', ' ', 'x', '=', '%', 'd', ',', 'y', '=', '%', 'd', '\n', 0};
        env.printf(c, (int) ptr->x, (int) ptr->y);
#endif
        ptr->failed = true;
    }

    return (struct module_args){
        .num_args = 1,
        .args = {
            [0] = create_value_integer((uint64_t) ptr),
        }};
}
