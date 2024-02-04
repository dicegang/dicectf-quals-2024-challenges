use std::collections::{HashMap, HashSet};

use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::seq::SliceRandom;

use crate::{Module, pshufb_inverse};
use crate::compile::{Graph, GraphEdge, Node, NodeOperation};
use crate::compile::NodeOperation::{Concat, ConstantString};

fn generate_random_permutation(rng: &mut StdRng, max: u8) -> Vec<u8> {
    let mut permutation: Vec<u8> = (0..max).collect();
    permutation.shuffle(rng);
    permutation
}

impl Graph {
    fn remove_node(&mut self, node_id: usize) {
        if let Some(index) = self.nodes.iter().position(|x| x.id == node_id) {
            let mut split = self.nodes.split_off(index);
            split.pop_front();
            self.nodes.append(&mut split);
        }
    }

    fn replace_outgoing_edges(&mut self, old_node_id: usize, new_node_id: usize) {
        let orig_edges: Vec<GraphEdge> = self.edges.clone();
        self.edges.clear();

        for edge in orig_edges {
            if edge.input_id != old_node_id {
                self.edges.push(edge.clone());
                continue;
            }

            self.edges.push(GraphEdge {
                input_id: new_node_id,
                output_id: edge.output_id,
                output_slot_id: edge.output_slot_id,
            })
        }

        let old_node = self
            .nodes
            .iter_mut()
            .find(|x| x.id == old_node_id)
            .unwrap()
            .num_outputs;
        let new_node = self.nodes.iter_mut().find(|x| x.id == new_node_id).unwrap();

        new_node.num_outputs = old_node;

        let old_node = self.nodes.iter_mut().find(|x| x.id == old_node_id).unwrap();
        old_node.num_outputs = 0;
    }
    fn replace_node(&mut self, old_node_id: usize, new_node_id: usize) {
        let orig_edges: Vec<GraphEdge> = self.edges.clone();
        self.edges.clear();

        for edge in orig_edges {
            self.edges.push(GraphEdge {
                input_id: if edge.input_id == old_node_id {
                    new_node_id
                } else {
                    edge.input_id
                },
                output_id: if edge.output_id == old_node_id {
                    new_node_id
                } else {
                    edge.output_id
                },
                output_slot_id: edge.output_slot_id,
            })
        }
        let inputs = self
            .nodes
            .iter_mut()
            .find(|x| x.id == old_node_id)
            .unwrap()
            .num_inputs;
        let outputs = self
            .nodes
            .iter_mut()
            .find(|x| x.id == old_node_id)
            .unwrap()
            .num_outputs;

        let new_node = self.nodes.iter_mut().find(|x| x.id == new_node_id).unwrap();
        new_node.num_outputs = outputs;
        self.remove_node(old_node_id);
    }
}

fn obfuscate_string_constants(rng: &mut StdRng, mut graph: Graph, pshufb: &Module) -> Graph {
    let mut string_nodes = HashMap::new();
    for node in &graph.nodes {
        if let ConstantString(s) = &node.operation {
            if node.num_inputs == 0 {
                string_nodes.insert(node.id, s.clone());
            }
        }
    }

    let pshufb = graph
        .insert_node(Node::new(ConstantString(pshufb.contents.clone())))
        .id;

    for (orig_id, str) in string_nodes {
        if str.len() < 16 {
            continue;
        }

        let chunks = str.chunks_exact(16);

        let mut node_id: Option<usize> = None;
        for chunk in chunks.clone() {
            let permutation: Vec<u8> = generate_random_permutation(rng, 16)
                .iter()
                .map(|x| x ^ 78)
                .collect();
            let permuted = pshufb_inverse(chunk, permutation.as_slice());

            // println!("{:?}", permutation);
            // println!("{:?}", permuted);
            // println!("{:?}", chunk);
            // println!("{:?}", pshufb_impl(&permuted.as_slice(), permutation.as_slice()));

            let str_node = graph
                .insert_node(Node::new(ConstantString(Vec::from(permuted))))
                .id;
            let permutation_node = graph.insert_node(Node::new(ConstantString(permutation))).id;
            let unshuffle_node = graph.insert_node(Node::new(NodeOperation::Execute)).id;
            graph.add_edge(pshufb, unshuffle_node);
            graph.add_edge(str_node, unshuffle_node);
            graph.add_edge(permutation_node, unshuffle_node);

            if let Some(id) = node_id {
                let concat_id = graph.insert_node(Node::new(Concat)).id;
                graph.add_edge(id, concat_id);
                graph.add_edge(unshuffle_node, concat_id);
                node_id = Some(concat_id)
            } else {
                node_id = Some(unshuffle_node);
            }
        }

        let remainder = chunks.remainder();
        if remainder.is_empty() {
            graph.replace_node(orig_id, node_id.unwrap());
            continue;
        }
        let remainder_id = graph
            .insert_node(Node::new(ConstantString(Vec::from(remainder))))
            .id;
        let concat_node = graph.insert_node(Node::new(Concat)).id;
        graph.add_edge(node_id.unwrap(), concat_node);
        graph.add_edge(remainder_id, concat_node);

        graph.replace_node(orig_id, concat_node)
    }

    graph
}

fn remove_unused_nodes(mut graph: Graph) -> Graph {
    let mut used_nodes = HashSet::new();

    for edge in &graph.edges {
        used_nodes.insert(edge.output_id);
        used_nodes.insert(edge.input_id);
    }

    let mut to_remove = vec![];
    for node in &graph.nodes {
        if !used_nodes.contains(&node.id) {
            to_remove.push(node.id);
        }
    }

    for id in to_remove {
        graph.remove_node(id);
    }

    graph
}

pub fn obfuscate(graph: Graph, pshufb: &Module) -> Graph {
    let graph = remove_unused_nodes(graph);
    let graph = obfuscate_string_constants(&mut StdRng::seed_from_u64(7891), graph, pshufb);
    let graph = remove_unused_nodes(graph);
    return graph;
}
