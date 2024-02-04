#![recursion_limit = "40960"]


use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Read;

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

use crate::compile::{compile, to_c_hex_string};
use crate::obfuscate::obfuscate;
use crate::parse::parse_program;
use crate::solve::solve;

mod compile;
mod parse;
mod obfuscate;
mod solve;

pub const FLAG: &str = "dice{l0wc0de_i5_tR3nDinG_7a2nchdaj12n}";


#[derive(Debug)]
struct Module {
    name: String,
    contents: Vec<u8>,
}

fn load_module(name: &str) -> Module {
    let mut module_add = File::open(format!("modules/module_{}.text", name)).expect("open failed");
    let mut buffer = vec![0; module_add.metadata().unwrap().len() as usize];
    module_add.read(&mut buffer).unwrap();
    Module {
        name: name.to_string(),
        contents: buffer,
    }
}

fn flag_hash(flag: &str) -> u32 {
    let mut i: u32 = 0;
    for (idx, x) in flag.bytes().enumerate() {
        if idx + 1 == flag.len() {
            i += 7 * (x as u32)
        } else {
            i ^= ((x as u32) ^ (idx as u32) ^ ((flag.as_bytes()[idx + 1] as u32)) + (x as u32 * 14));
        }
    }
    return i;
}

pub fn pshufb_impl(source: &[u8], control: &[u8]) -> Vec<u8> {
    // source[mapping[control ^ 78]]
    let mapping = [15, 13, 7, 8, 5, 3, 6, 4, 14, 0, 2, 11, 9, 12, 10, 1];

    let mut ret: [u8; 16] = Default::default();
    for i in 0..16 {
        ret[i] = source[mapping[(control[i] ^ 78) as usize]];
    }
    return Vec::from(&ret);
}

pub fn pshufb_inverse(source: &[u8], control: &[u8]) -> Vec<u8> {
    // source

    let mapping = [15, 13, 7, 8, 5, 3, 6, 4, 14, 0, 2, 11, 9, 12, 10, 1];

    let mut ret = [0u8; 16];
    for i in 0..16 {
        ret[mapping[(control[i] ^ 78) as usize]] = source[i]
    }
    Vec::from(ret)
}

fn half_hash(half: &[u8]) -> usize {
    let mut ret = 0usize;
    for i in 0..16 {
        if (i & 1) == 1 {
            ret += 238 * (half[i & 15] as usize);
        } else {
            ret += 90187 * (half[i & 15] as usize);
        }
    }

    ret
}


pub const UR: u64 = 0;
pub const U: u64 = 1;
pub const UL: u64 = 2;
pub const L: u64 = 3;
pub const R: u64 = 4;
pub const DR: u64 = 5;
pub const D: u64 = 6;
pub const DL: u64 = 7;

fn generate_maze(rng: &mut StdRng) -> Option<(Vec<Module>, String, u64, (HashMap<u8, Vec<u64>>, [[bool; 128]; 128]))> {
    let input = "we0D3R0__lditn5c7n_h2cnjGdan21ia";

    let mut x: isize = 64;
    let mut y: isize = 64;
    let mut walls: [[bool; 128]; 128] = [[false; 128]; 128];

    let mut visited = vec![];

    let mut action_map: HashMap<u8, Vec<u64>> = HashMap::new();

    let is_valid = |new_x: isize, new_y: isize, visited: &Vec<(isize, isize)>, walls: [[bool; 128]; 128]| -> bool {
        return (0 <= new_x) && (new_x < 128)
            && (0 <= new_y) && (new_y < 128)
            && !walls[new_x as usize][new_y as usize]
            && !visited.contains(&(new_x, new_y))
            && (if visited.contains(&(new_x + 1, new_y - 1)) { 1 } else { 0 } +
            if visited.contains(&(new_x + 1, new_y)) { 1 } else { 0 } +
            if visited.contains(&(new_x + 1, new_y + 1)) { 1 } else { 0 } +
            if visited.contains(&(new_x, new_y + 1)) { 1 } else { 0 } +
            if visited.contains(&(new_x, new_y - 1)) { 1 } else { 0 } +
            if visited.contains(&(new_x - 1, new_y - 1)) { 1 } else { 0 } +
            if visited.contains(&(new_x - 1, new_y)) { 1 } else { 0 } +
            if visited.contains(&(new_x - 1, new_y - 1)) { 1 } else { 0 }) <= 1;
    };

    for c in input.bytes() {
        let mut actions = vec![];
        let mut attempts = 0;
        loop {
            let option = if action_map.contains_key(&c) {
                if attempts == 3 {
                    return None;
                }
                action_map.get(&c).unwrap()[attempts]
            } else {
                rng.gen_range(0..8)
            };

            let mut newx = x;
            let mut newy = y;
            if option == UR {
                newx = x + 1;
                newy = y + 1;
            } else if option == U {
                newy = y + 1;
            } else if option == UL {
                newx = x - 1;
                newy = y + 1;
            } else if option == L {
                newx = x - 1;
            } else if option == R {
                newx = x + 1;
            } else if option == DR {
                newx = x + 1;
                newy = y - 1;
            } else if option == D {
                newy = y - 1;
            } else if option == DL {
                newx = x - 1;
                newy = y - 1;
            } else {
                unreachable!();
            }

            if is_valid(newx, newy, &visited, walls) {
                actions.push(option);
                visited.push((x, y));
                visited.push((newx, newy));
                x = newx;
                y = newy;
                // println!("{} {} {}", action_map.len(), x, y);
                println!("op={} x={} y={} result={}", option, x, y, (x << 16) | y);
                if actions.len() == 3 {
                    break;
                }
            } else {
                if attempts == 10 {
                    return None;
                }
            }
            attempts += 1;
        }
        action_map.insert(c, actions);
    }

    let result = ((x as u64) << 16) | (y as u64);

    // fn generate_mapping(x: u8, action_map: &HashMap<u8, Vec<u64>>, idx: usize) -> String {
    //     if (x == 127) {
    //         return String::from("\"unreachable\"");
    //     }
    //     let mut rng = StdRng::seed_from_u64(x as u64);
    //     let mut m1 = rng.gen_range(0..8);
    //     if action_map.contains_key(&x) {
    //         m1 = action_map[&x][idx];
    //     }
    //     let recursed = generate_mapping(x + 1, action_map, idx);
    //     return format!("(if (eq? x {x}) {m1} {recursed})");
    // }

    fn generate_mapping(x: u8, action_map: &HashMap<u8, Vec<u64>>, idx: usize) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(x as u64);

        let mut ret: Vec<u8> = vec![];
        for i in 0..=255 {
            if i == 238 {
                ret.push(0);
            } else if action_map.contains_key(&i) {
                ret.push(action_map[&i][idx] as u8)
            } else {
                ret.push(rng.gen_range(0..=8u8))
            }
        }
        return ret;
    }

    fn generate_maze_fn(x: isize, y: isize, visited: &Vec<(isize, isize)>, walls: &mut [[bool; 128]; 128]) -> String {
        if x == 128 && y == 128 {
            return String::from("maze");
        }

        if x == 129 {
            return generate_maze_fn(0, y + 1, visited, walls);
        }

        if visited.contains(&(x, y)) {
            return generate_maze_fn(x + 1, y, visited, walls);
        }

        if visited.contains(&(x + 1, y)) ||
            visited.contains(&(x + 1, y - 1)) ||
            visited.contains(&(x + 1, y + 1)) ||
            visited.contains(&(x, y + 1)) ||
            visited.contains(&(x, y)) ||
            visited.contains(&(x, y - 1)) ||
            visited.contains(&(x - 1, y + 1)) ||
            visited.contains(&(x - 1, y)) ||
            visited.contains(&(x - 1, y - 1)) {
            walls[x as usize][y as usize] = true;

            let recursed = generate_maze_fn(x + 1, y, visited, walls);

            return String::from(format!("(maze_set {recursed} {x} {y})"));
        }

        return generate_maze_fn(x + 1, y, visited, walls);
    }

    let maze_fn = generate_maze_fn(0, 0, &visited, &mut walls);

    for i in 0..128isize {
        for j in 0..128isize {
            if (i, j) == (x, y) {
                print!("o")
            } else if walls[i as usize][j as usize] {
                print!("#")
            } else {
                print!("{}", if visited.contains(&(i, j)) { "x" } else { " " });
            }
        }
        println!()
    }

    let modules = vec![
        Module {
            name: "move1".to_string(),
            contents: generate_mapping(0, &action_map, 0),
        },
        Module {
            name: "move2".to_string(),
            contents: generate_mapping(0, &action_map, 1),
        },
        Module {
            name: "move3".to_string(),
            contents: generate_mapping(0, &action_map, 2),
        },
    ];
    println!("{:?}", modules[0]);

    Some((modules, format!("(define (setup_maze maze) {maze_fn})\n"), result, (action_map, walls)))
}

fn main() -> Result<(), Box<dyn Error>> {
    assert_eq!(FLAG.len(), 38);

    let seed = 86;
    let (mut addn_modules, maze_mappings, maze_result, (action_map, walls)) = loop {
        let mut rng = StdRng::seed_from_u64(seed);
        if let Some(y) = generate_maze(&mut rng) {
            break y;
        }
        unreachable!();
    };

    let flag_len = FLAG.len();
    let flag_len_plus_two = FLAG.len() + 2;
    let flag_len_minus_1 = FLAG.len() - 1;
    let flag_hash_value = flag_hash(FLAG);

    let real_flag = &FLAG[5..flag_len_minus_1];
    let half1 = &real_flag[0..16];
    let half2 = &real_flag[16..32];

    let control1_string = [10, 6, 15, 0, 1, 13, 7, 2, 14, 9, 4, 3, 11, 8, 12, 5].map(|x| x ^ 78);
    let control1_cstring = to_c_hex_string(&control1_string);
    let control2_string = [7, 2, 5, 12, 8, 3, 0, 13, 10, 14, 11, 15, 6, 1, 9, 4].map(|x| x ^ 78);
    let control2_cstring = to_c_hex_string(&control2_string);

    let scrambled1 = pshufb_impl(half1.as_bytes(), &control1_string);
    let scrambled2 = pshufb_impl(half2.as_bytes(), &control2_string);

    let half_hash1 = half_hash(scrambled1.as_slice());
    let half_hash2 = half_hash(scrambled2.as_slice());

    solve(&action_map, &walls, maze_result, half_hash1, half_hash2, control1_string, control2_string, flag_hash_value);

    let data = format!(r#"(

    (define (neq? a b) (evaluate xor a b))
    (define (eq? a b) (evaluate not (evaluate xor a b)))
    (define (and? a b) (evaluate and a b))
    (define (or? a b) (evaluate or a b))

    (define (at str x) (substr str x 3735928559))

    (define (maze_op ptr op) (evaluate maze ptr op))
    (define (maze_new) (maze_op 0 0))
    (define (maze_set ptr x y) (evaluate maze ptr 10 x y))
    (define (maze_remove ptr x y) (evaluate maze ptr 11 x y))
    (define (maze_get_result ptr val) (maze_op ptr 12))

    {maze_mappings}

    (define (get_flag_len_ acc x)
        (if
            (neq? (evaluate get_flag_char x) 0)
            (+ acc 1)
            acc
            ))
    (define (get_flag_len) (seqfoldl! {flag_len_plus_two} 0 get_flag_len_))

    (define (hash_flag_all_ acc x flag_len)
        (if (eq? (+ x 1) flag_len)
            (+ acc (* 7 (evaluate get_flag_char x)))
            (evaluate xor acc x (evaluate get_flag_char x) (+ (* 14 (evaluate get_flag_char x)) (evaluate get_flag_char (+ x 1))))))
    (define (hash_flag_all flag_len) (seqfoldl! {flag_len} 0 hash_flag_all_ flag_len))

    (define (check_basics)
        (let (flag_len (get_flag_len))
            (evaluate and
                (eq? flag_len {flag_len})
                (eq? (hash_flag_all flag_len) {flag_hash_value})
                (eq? 100 (evaluate get_flag_char 0))
                (eq? 105 (evaluate get_flag_char 1))
                (eq? 99 (evaluate get_flag_char 2))
                (eq? 101 (evaluate get_flag_char 3))
                (eq? 123 (evaluate get_flag_char 4))
                (eq? 125 (evaluate get_flag_char {flag_len_minus_1}))
        )))

    (define (domaze_ acc x m f)
        (if (or? (eq? x 32) (eq? x 33))
            (evaluate maze m 12 x)
            (let (y (if (eq? x 32) 255 (at f x)))
                (+ acc (* 0
                    (evaluate maze
                        (evaluate maze
                            (evaluate maze m (at move1 y) 1)
                            (at move2 y) 2)
                        (at move3 y) 3))
                ))))

    (define (domaze input)
        (if (eq?
                {maze_result}
                (let (ptr (setup_maze (maze_new)))
                    (seqfoldl! 33 0 domaze_ ptr input)))
            1
            0))

    (define (check2 scrambled status)
        (and? (domaze (substr scrambled 0 32)) status))

    (define (checkhalf_ acc x half)
            (if (evaluate and x 1)
                (+ acc (* 238 (at half (evaluate and x 15))))
                (+ acc (* 90187 (at half (evaluate and x 15))))))

    (define (checkhalf which half status)
        (and? status
            (if (eq? which 1)
                (eq? {half_hash1} (seqfoldl! 16 0 checkhalf_ half))
                (eq? {half_hash2} (seqfoldl! 16 0 checkhalf_ half)))
                ))

    (define (check1 status)
        (let (real_flag (substr (get_flag) 5 {flag_len_minus_1}))
            (let (half1 (evaluate pshufb (substr real_flag 0 16) "{control1_cstring}"))
                (let (half2 (evaluate pshufb (substr real_flag 16 32) "{control2_cstring}"))
                    (check2 (concat half1 half2) (checkhalf 1 half1 (checkhalf 2 half2 status)))))))

    (define (main) (exit (if (check1 (check_basics)) "SUCCESS" "FAILURE")))
))"#);


    let program = parse_program(&data);

    let mut modules = vec![
        load_module("add"),
        load_module("pshufb"),
        load_module("get_flag_char"),
        load_module("xor"),
        load_module("maze"),
        load_module("and"),
        load_module("not"),
        load_module("or"),
    ];

    modules.append(&mut addn_modules);

    println!("{}", data);
    println!("{}", String::from_utf8(scrambled1).unwrap());
    println!("{}", String::from_utf8(scrambled2).unwrap());

    let graph = compile(program, &modules);
    println!("Nodes: {} Edges: {}", graph.nodes.len(), graph.edges.len());
    fs::write("graph.dot", format!("digraph G {{ {} }}", graph.to_dot(&modules))).expect("Unable to write file");

    let obfuscated = obfuscate(graph, &load_module("pshufb"));
    println!("Nodes: {} Edges: {}", obfuscated.nodes.len(), obfuscated.edges.len());
    fs::write("graph.obf.dot", format!("digraph G {{ {} }}", obfuscated.to_dot(&modules))).expect("Unable to write file");
    fs::write("graph.c", format!("#include \"nodes.h\"\n#include \"loader.h\"\n#include \"core.h\"\n{}", obfuscated.to_c())).expect("Unable to write file");

    println!("result should be {}", maze_result);

    return Ok(());
}
