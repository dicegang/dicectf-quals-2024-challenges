use std::collections::{HashMap, LinkedList, VecDeque};
use std::iter::zip;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::compile::NodeOperation::{ConstantNumber, ConstantString};
use crate::Module;
use crate::parse::{Ast, Definition, Operation, Program};

#[derive(Debug, Clone)]
pub enum NodeOperation {
    Add,
    Execute,
    Substring,
    Concat,
    Flag,
    Multiply,
    If,
    Exit,
    ConstantNumber(u64),
    ConstantString(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: usize,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub operation: NodeOperation,
}

pub static NODE_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl Node {
    pub fn new(node_operation: NodeOperation) -> Node {
        Node {
            id: NODE_COUNTER.fetch_add(1, Ordering::Relaxed),
            num_inputs: 0,
            num_outputs: 0,
            operation: node_operation,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct GraphEdge {
    pub input_id: usize,
    pub output_id: usize,
    pub output_slot_id: usize,
}

#[derive(Debug)]
pub struct Graph {
    pub nodes: LinkedList<Node>,
    pub edges: Vec<GraphEdge>,
}

pub fn to_c_hex_string(data: &[u8]) -> String {
    let mut hex_string = String::new();

    for &byte in data {
        hex_string.push_str("\\x");
        hex_string.push_str(&format!("{:02x}", byte));
    }

    hex_string
}

impl Graph {
    pub fn insert_node(&mut self, node: Node) -> &mut Node {
        self.nodes.push_back(node);
        return self.nodes.back_mut().unwrap();
    }

    pub fn find_node(&mut self, id: usize) -> &mut Node {
        return self.nodes.iter_mut().find(|x| x.id == id).unwrap();
    }

    pub fn add_edge(&mut self, input: usize, output: usize) {
        let input_node = self.find_node(input);
        input_node.num_outputs += 1;
        let output_node = self.find_node(output);
        output_node.num_inputs += 1;
        self.edges.push(GraphEdge {
            input_id: input,
            output_id: output,
            output_slot_id: 0,
        });
    }

    pub fn to_dot(&self, modules: &Vec<Module>) -> String {
        let mut output = String::new();

        let mut module_lookup = HashMap::new();

        for node in &self.nodes {
            let mut skip_label_output = false;
            if let ConstantString(x) = &node.operation {
                for module in modules {
                    if &module.contents == x {
                        skip_label_output = true;
                        output += &*format!("module {}", module.name);
                        module_lookup.insert(node.id, &module.name);
                        break;
                    }
                }
            }
            output += &*format!("{}[label=\"{} ", node.id, node.id);
            if let NodeOperation::Execute = &node.operation {
                for edge in &self.edges {
                    if edge.output_id == node.id {
                        if let Some(m) = module_lookup.get(&edge.input_id) {
                            output += &*format!("Execute {}", m);
                            skip_label_output = true;
                            break;
                        }
                    }
                }
            }
            if !skip_label_output {
                output += &*format!("{:?}", node.operation).replace("\"", "'");
            }
            output += "\"]\n"
        }
        let mut hash = HashMap::new();
        for edge in &self.edges {
            let mut label = 1;
            if hash.contains_key(&edge.output_id) {
                label = hash.get(&edge.output_id).unwrap() + 1
            }
            hash.insert(edge.output_id, label);

            if module_lookup.contains_key(&edge.input_id) {
                continue;
            }
            output += &*format!(
                "{} -> {} [label={}]\n",
                edge.input_id, edge.output_id, label
            );
        }

        output
    }

    pub fn to_c(&self) -> String {
        let mut output = String::new();

        let mut prev = "NULL".to_string();

        for node in &self.nodes {
            let operation = match node.operation {
                NodeOperation::Execute => "NODE_EXECUTE",
                NodeOperation::Add => "NODE_ADDITION",
                NodeOperation::Multiply => "NODE_MULTIPLY",
                NodeOperation::If => "NODE_IF",
                NodeOperation::Flag => "NODE_FLAG",
                NodeOperation::Substring => "NODE_SUBSTRING",
                NodeOperation::Exit => "NODE_EXIT",
                NodeOperation::Concat => "NODE_CONCAT",
                ConstantNumber(_) => "NODE_CONSTANT",
                ConstantString(_) => "NODE_CONSTANT",
            };

            output += &*format!(
                "\
                struct loader_graph_node_list loader_node_list_{} = {{
                    .next = {},
                    .value = {{
                        .id = {},
                        .num_inputs = {},
                        .num_outputs = {},
                        .node_kind = {},
            ",
                node.id, prev, node.id, node.num_inputs, node.num_outputs, operation
            );
            if let ConstantNumber(x) = &node.operation {
                output += &*format!(".value = create_value_integer({}ULL),", x);
            }
            if let ConstantString(x) = &node.operation {
                output += &*format!(
                    ".value = create_value_string_from_literal(\"{}\"),",
                    to_c_hex_string(x)
                );
            }
            output += "},\n};\n";

            prev = "&loader_node_list_".to_string() + &*node.id.to_string();
        }

        output += &*format!(
            "\
                struct loader_graph_node_list *loader_node_list = {};
            ",
            prev
        );

        prev = "NULL".to_string();
        let mut i = 0;
        for edge in &self.edges {
            output += &*format!(
                "\
                struct loader_graph_edge_list loader_edge_list_{} = {{
                    .next = {},
                    .value = {{.output_node_id = {}, .input_node_id= {}}},
                }};
            ",
                i, prev, edge.output_id, edge.input_id
            );
            prev = "&loader_edge_list_".to_string() + &*i.to_string();
            i += 1;
        }

        output += &*format!(
            "\
                struct loader_graph_edge_list *loader_edge_list = {};
        ",
            prev
        );

        return output;
    }
}

#[derive(Debug, Clone)]
struct EnvironmentEntry {
    identifier: String,
    output_node_id: usize,
}

#[derive(Debug, Clone)]
pub struct Environment {
    entries: VecDeque<EnvironmentEntry>,
}

impl Environment {
    #[must_use]
    pub fn add_variable(&self, identifier: &String, node_id: usize) -> Environment {
        let mut copy = self.clone();
        copy.entries.push_back(EnvironmentEntry {
            identifier: identifier.clone(),
            output_node_id: node_id,
        });
        copy
    }

    pub fn new() -> Environment {
        Environment {
            entries: Default::default(),
        }
    }

    fn find_variable_node_id(&self, identifier: &String) -> usize {
        self.entries
            .iter()
            .rfind(|x| x.identifier == *identifier)
            .expect(&*format!("could not find identifier {identifier}"))
            .output_node_id
    }
}

fn compile_string(graph: &mut Graph, string: NodeOperation) -> usize {
    graph.insert_node(Node::new(string)).id
}

fn compile_ast(
    program: &Program,
    graph: &mut Graph,
    environment: &Environment,
    ast: &Ast,
) -> usize {
    match ast {
        Ast::Apply { op, args } => {
            let mut arg_node_ids = vec![];
            for arg in args {
                arg_node_ids.push(compile_ast(program, graph, environment, arg.as_ref()))
            }

            let mut should_add_edges = true;
            let node = match op {
                Operation::Add() => graph.insert_node(Node::new(NodeOperation::Add)).id,
                Operation::Multiply() => graph.insert_node(Node::new(NodeOperation::Multiply)).id,
                Operation::If() => graph.insert_node(Node::new(NodeOperation::If)).id,
                Operation::EvaluateX86() => graph.insert_node(Node::new(NodeOperation::Execute)).id,
                Operation::Substring() => graph.insert_node(Node::new(NodeOperation::Substring)).id,
                Operation::Concat() => graph.insert_node(Node::new(NodeOperation::Concat)).id,
                Operation::Exit() => graph.insert_node(Node::new(NodeOperation::Exit)).id,
                Operation::GetFlag() => graph.insert_node(Node::new(NodeOperation::Flag)).id,
                Operation::UserDefined { name } => {
                    let definition = program
                        .definitions
                        .iter()
                        .find(|x| x.name == *name)
                        .expect(&*format!("could not find definition for {}", name));
                    let mut updated_enviroment = environment.clone();
                    for (arg_node, arg) in zip(&arg_node_ids, &definition.args) {
                        updated_enviroment = updated_enviroment.add_variable(&arg, *arg_node);
                    }
                    should_add_edges = false;
                    compile_definition(program, graph, definition, updated_enviroment)
                }
            };

            if should_add_edges {
                for arg_node_id in &arg_node_ids {
                    graph.add_edge(*arg_node_id, node);
                }
            }
            node
        }
        Ast::Number(x) => {
            graph
                .insert_node(Node::new(NodeOperation::ConstantNumber(*x)))
                .id
        }
        Ast::String(x) => {
            graph
                .insert_node(Node::new(NodeOperation::ConstantString(Vec::from(
                    x.as_bytes(),
                ))))
                .id
        }
        Ast::Identifier { name } => environment.find_variable_node_id(name),
        Ast::Let {
            var_name,
            value,
            body,
        } => {
            let node = compile_ast(program, graph, environment, value);
            compile_ast(
                program,
                graph,
                &environment.add_variable(var_name, node),
                body,
            )
        }
    }
}

fn compile_definition(
    program: &Program,
    graph: &mut Graph,
    definition: &Definition,
    environment: Environment,
) -> usize {
    compile_ast(program, graph, &environment, &definition.body)
}

pub(crate) fn compile(program: Program, modules: &Vec<Module>) -> Graph {
    let mut graph = Graph {
        nodes: LinkedList::new(),
        edges: vec![],
    };

    let mut environment = Environment::new();
    for module in modules {
        environment = environment.add_variable(
            &module.name,
            compile_string(&mut graph, ConstantString(module.contents.clone())),
        );
    }

    for definition in &program.definitions {
        if definition.name == "main" {
            println!("main is at node id={}", compile_definition(&program, &mut graph, definition, environment.clone()));
        }
    }

    graph
}
