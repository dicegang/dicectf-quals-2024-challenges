#pragma once

#include "nodes.h"

struct loader_graph_edge {
    size_t input_node_id;
    size_t output_node_id;
    size_t output_slot_id;
};

struct loader_graph_node {
    size_t id;
    size_t num_inputs;
    size_t num_outputs;
    enum node_kind node_kind;
    struct value value;
};

struct loader_graph_edge_list {
    struct loader_graph_edge_list *next;
    struct loader_graph_edge value;
};

struct loader_graph_node_list {
    struct loader_graph_node_list *next;
    struct loader_graph_node value;
};

struct loaded_graph {
    struct graph_node *nodes;
    size_t node_count;
};


struct loaded_graph load_graph(struct loader_graph_edge_list const *const edge_list, struct loader_graph_node_list const *const node_list) {
    size_t max_node_id = 0;
    for (struct loader_graph_node_list const *node = node_list; node != NULL; node = node->next) {
        max_node_id = MAX(max_node_id, node->value.id);
    }

    struct graph_node *nodes = calloc(max_node_id + 1, sizeof(*nodes));
    size_t *inputs_remaining = calloc(max_node_id + 1, sizeof(size_t));
    size_t *outputs_remaining = calloc(max_node_id + 1, sizeof(size_t));

    for (struct loader_graph_node_list const *node = node_list; node != NULL; node = node->next) {
        struct loader_graph_node node_value = node->value;

        nodes[node_value.id] = (struct graph_node){
#ifdef DEBUG
            .node_id = node_value.id,
#endif
            .kind = node_value.node_kind,
            .num_outputs = node_value.num_outputs,
            .num_inputs = node_value.num_inputs,
            .output_slots = calloc(node_value.num_outputs, sizeof(struct value *)),
            .input_slots = calloc(node_value.num_inputs, sizeof(struct value)),
            .constant = node_value.value};
        inputs_remaining[node_value.id] = node_value.num_inputs - 1;
        outputs_remaining[node_value.id] = node_value.num_outputs - 1;
    }


    for (struct loader_graph_edge_list const *edge = edge_list; edge != NULL; edge = edge->next) {
        struct loader_graph_edge edge_value = edge->value;
        nodes[edge_value.input_node_id].output_slots[outputs_remaining[edge_value.input_node_id]--] = &nodes[edge_value.output_node_id].input_slots[inputs_remaining[edge_value.output_node_id]--];
        DEBUG("id:%zu->id:%zu[%zu] val:%p", edge_value.input_node_id, edge_value.output_node_id, inputs_remaining[edge_value.output_node_id] + 1, nodes[edge_value.input_node_id].output_slots[edge_value.output_slot_id]);
    }

    free(inputs_remaining);

    return (struct loaded_graph){
        .node_count = max_node_id + 1,
        .nodes = nodes,
    };
}
