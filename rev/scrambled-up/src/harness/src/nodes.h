#pragma once

#include <inttypes.h>
#include <string.h>
#include <sys/mman.h>

#include "core.h"
#include "util.h"

#define ENUMERATE_NODE_KINDS(X) \
    X(NODE_NOOP)                \
    X(NODE_ADDITION)            \
    X(NODE_MULTIPLY)            \
    X(NODE_CONSTANT)            \
    X(NODE_EXECUTE)             \
    X(NODE_IF)                  \
    X(NODE_REVERSE)             \
    X(NODE_SELECT)              \
    X(NODE_EXIT)                \
    X(NODE_FLAG)                \
    X(NODE_CONCAT)              \
    X(NODE_SUBSTRING)

enum node_kind {
#define X(name) name,
    ENUMERATE_NODE_KINDS(X)
#undef X
};

#ifndef NDEBUG
char const *node_kind_to_string(enum node_kind kind) {
    switch (kind) {
#define X(name) \
    case name:  \
        return #name;
        ENUMERATE_NODE_KINDS(X)
#undef X
    }
    ASSERT(false, "unknown node kind %d", (int) kind);
}
#endif

#undef ENUMERATE_NODE_KINDS

void *global_execution_buffer;
struct value_string *flag_buffer;
#define EXECUTION_BUFFER_SIZE (1024 * 1024 * 15)

struct graph_node {
#ifdef DEBUG
    size_t node_id;
#endif
    enum node_kind kind;
    size_t num_inputs;
    struct value *input_slots;
    size_t num_outputs;
    struct value **output_slots;

    union {
        struct value constant;
    };
};

void write_value_to_outputs(struct graph_node *node, struct value value) {
    if (value.kind == VALUE_INTEGER) {
        DEBUG("result: %zu", value.integer);
    } else {
        DEBUG("result: %.*s", (int) value.string.length, (char *) value.string.data);
    }
    for (size_t i = 0; i < node->num_outputs; ++i) {
        *node->output_slots[i] = value;
    }
}

void evaluate_graph_node_addition(struct graph_node *node) {
    ASSERT(node->kind == NODE_ADDITION);

    if (node->input_slots[0].kind == VALUE_STRING) {
        struct value v = create_value_string(node->input_slots[0].string.data, node->input_slots[0].string.length);
        v.string.data[node->input_slots[1].integer] += node->input_slots[2].integer;
        write_value_to_outputs(node, v);
        return;
    }

    uint64_t result = 0;
    for (size_t i = 0; i < node->num_inputs; ++i) {
        struct value const *input = &node->input_slots[i];
        ASSERT(input->kind == VALUE_INTEGER);

        result += input->integer;
    }

    write_value_to_outputs(node, create_value_integer(result));
}

void evaluate_graph_node_if(struct graph_node *node) {
    ASSERT(node->kind == NODE_IF);

    if (node->input_slots[0].integer) {
        write_value_to_outputs(node, node->input_slots[1]);
    } else {
        write_value_to_outputs(node, node->input_slots[2]);
    }
}

void evaluate_graph_node_exit(struct graph_node *node) {
    ASSERT(node->kind == NODE_EXIT);

    if (strcmp((char *) node->input_slots[0].string.data, "SUCCESS") == 0) {
        printf("%.*s: Correct Flag! :)\n", (int) node->input_slots[0].string.length, (char *) node->input_slots[0].string.data);
        fflush(stdout);
        exit(0);
    }

    printf("%.*s: Incorrect Flag! :(\n", (int) node->input_slots[0].string.length, (char *) node->input_slots[0].string.data);
    fflush(stdout);
    exit(1);
}

void evaluate_graph_node_flag(struct graph_node *node) {
    ASSERT(node->kind == NODE_FLAG);

    write_value_to_outputs(node, (struct value){
                                     .kind = VALUE_STRING,
                                     .string = *flag_buffer,
                                 });
}

void evaluate_graph_node_substring(struct graph_node *node) {
    ASSERT(node->kind == NODE_SUBSTRING);
    ASSERT(node->num_inputs == 3);

    struct value_string str = node->input_slots[0].string;
    size_t start = node->input_slots[1].integer;
    size_t end = node->input_slots[2].integer;

    if (end == 0xdeadbeef) {
        write_value_to_outputs(node, create_value_integer(str.data[start]));
        return;
    }

    uint8_t *new_backing = malloc(end - start);
    size_t new_i = 0;
    for (size_t i = start; i < end; ++i, ++new_i) {
        new_backing[new_i] = str.data[i];
    }

    write_value_to_outputs(node, create_value_string(new_backing, end - start));
}

void evaluate_graph_node_concat(struct graph_node *node) {
    ASSERT(node->kind == NODE_CONCAT);
    ASSERT(node->num_inputs == 2);

    struct value_string str = node->input_slots[0].string;
    struct value_string str2 = node->input_slots[1].string;

    uint8_t *new_backing = malloc(str.length + str2.length);
    size_t i = 0;
    for (size_t j = 0; j < str.length; ++j, ++i) {
        new_backing[i] = str.data[j];
    }
    for (size_t j = 0; j < str2.length; ++j, ++i) {
        new_backing[i] = str2.data[j];
    }

    write_value_to_outputs(node, create_value_string(new_backing, str.length + str2.length));
}

void evaluate_graph_node_multiply(struct graph_node *node) {
    ASSERT(node->kind == NODE_MULTIPLY);

    uint64_t result = 1;
    for (size_t i = 0; i < node->num_inputs; ++i) {
        struct value const *input = &node->input_slots[i];
        ASSERT(input->kind == VALUE_INTEGER);

        result *= input->integer;
    }

    write_value_to_outputs(node, create_value_integer(result));
}

void evaluate_graph_node_reverse(struct graph_node *node) {
    ASSERT(node->kind == NODE_REVERSE);
    ASSERT(node->num_inputs == node->num_outputs);

    for (size_t i = 0; i < node->num_inputs; ++i) {
        *node->output_slots[node->num_outputs - i] = node->input_slots[i];
    }
}

void evaluate_graph_node_constant(struct graph_node *node) {
    ASSERT(node->kind == NODE_CONSTANT);
    write_value_to_outputs(node, node->constant);
}

void *env_calloc(size_t r) {
    return calloc(1, r);
}

void evaluate_graph_node_execute(struct graph_node *node) {
    ASSERT(node->kind == NODE_EXECUTE);
    ASSERT(node->num_inputs > 0);

    mprotect(global_execution_buffer, EXECUTION_BUFFER_SIZE, PROT_READ | PROT_WRITE);
    memcpy(global_execution_buffer, node->input_slots[0].string.data, node->input_slots[0].string.length);
    mprotect(global_execution_buffer, EXECUTION_BUFFER_SIZE, PROT_READ | PROT_EXEC);

    struct module_args input_args = {
        .num_args = node->num_inputs - 1,
    };
    for (size_t i = 1; i < node->num_inputs; ++i) {
        input_args.args[i - 1] = node->input_slots[i];
    }

    struct module_args (*f)(struct module_args, struct module_env) = global_execution_buffer;
    struct module_args output = f(input_args, (struct module_env){
                                                  .flag = *flag_buffer,
                                                  .free = free,
#ifdef ISDEBUG
                                                  .printf = printf,
#endif
                                                  .malloc = env_calloc,
                                              });

    fflush(stdout);
    if (output.args[0].kind == VALUE_STRING) {
        DEBUG("Got string %s", output.args[0].string.data);
    } else {
        DEBUG("Got integer %zu", output.args[0].integer);
    }

    write_value_to_outputs(node, output.args[0]);
}

void evaluate_graph_node(struct graph_node *node) {
    void (*fns[])(struct graph_node *) = {
        [NODE_ADDITION] = evaluate_graph_node_addition,
        [NODE_MULTIPLY] = evaluate_graph_node_multiply,
        [NODE_CONSTANT] = evaluate_graph_node_constant,
        [NODE_EXECUTE] = evaluate_graph_node_execute,
        [NODE_IF] = evaluate_graph_node_if,
        [NODE_SUBSTRING] = evaluate_graph_node_substring,
        [NODE_FLAG] = evaluate_graph_node_flag,
        [NODE_CONCAT] = evaluate_graph_node_concat,
        [NODE_EXIT] = evaluate_graph_node_exit,
    };

    DEBUG("executing node id=%zu, %s", node->node_id, node_kind_to_string(node->kind));

    fns[node->kind](node);
}