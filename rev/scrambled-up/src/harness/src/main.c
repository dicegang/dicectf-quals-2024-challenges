#include <stdio.h>
#include <sys/mman.h>

#include "core.h"
#include "loader.h"
#include "nodes.h"

#include "gen.c"
#include <signal.h>

extern struct loader_graph_edge_list *loader_edge_list;
extern struct loader_graph_node_list *loader_node_list;

void evaluate_graph(size_t node_count, struct graph_node *nodes) {
    bool *have_executed = calloc(node_count, sizeof(*have_executed));

    while (1) {
        bool did_something = false;
        for (size_t i = 0; i < node_count; ++i) {
            if (have_executed[i]) {
                continue;
            }

            bool all_inputs_ready = true;
            struct graph_node *node = &nodes[i];
            if (node->kind == NODE_NOOP) {
                have_executed[i] = true;
                continue;
            }
            for (size_t j = 0; j < node->num_inputs; ++j) {
                if (node->input_slots[j].kind == VALUE_EMPTY) {
                    all_inputs_ready = false;
                    // DEBUG("input id=%d j=%d not ready node->input_slots[j].kind=%d", node->node_id, j, node->input_slots[j].kind);
                    break;
                }
            }
            if (!all_inputs_ready) {
                continue;
            }

            evaluate_graph_node(node);

            have_executed[i] = true;
            did_something = true;
        }

        if (!did_something) {
            DEBUG("State:");
            for (size_t i = 0; i < node_count; ++i) {
                DEBUG("\tNode %zu%s%c ", nodes[i].node_id, have_executed[i] ? " [finished]" : "", nodes[i].num_inputs ? ':' : ' ');
                for (size_t j = 0; j < nodes[i].num_inputs; ++j) {
                    DEBUG("\t\tInput %zu - %d", j, (int) nodes[i].input_slots[j].kind);
                }
                // if (nodes[i].num_outputs == 0) {
                // DEBUG("\tResult: %zu", nodes[i])
                // }
            }

            ASSERT(did_something);
        }

        bool done = true;
        for (size_t i = 0; i < node_count; ++i) {
            done &= have_executed[i];
        }

        if (done) {
            break;
        }
    }

    free(have_executed);
}

void on_segv(int) {
    printf("Invalid flag.\n");
    exit(1);
}

int main(int argc, char **argv) {
    signal(SIGSEGV, on_segv);

    char *flag_string;
    size_t size;

    printf("Enter the flag: ");
    fflush(stdout);

    getline(&flag_string, &size, stdin);

    if (flag_string[strlen(flag_string) - 1] == '\n') {
        flag_string[strlen(flag_string) - 1] = 0;
    }


    struct value flag = create_value_string(flag_string, strlen(flag_string));
    flag_buffer = &flag.string;

    global_execution_buffer = mmap(NULL, EXECUTION_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0,
                                   0);

    struct loaded_graph graph = load_graph(loader_edge_list, loader_node_list);
    evaluate_graph(graph.node_count, graph.nodes);


    munmap(global_execution_buffer, EXECUTION_BUFFER_SIZE);
}