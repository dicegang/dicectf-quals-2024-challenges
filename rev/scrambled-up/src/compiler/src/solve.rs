use std::collections::HashMap;
use crate::{D, DL, DR, FLAG, flag_hash, half_hash, L, pshufb_inverse, R, U, UL, UR};

pub fn solve_maze_rec(action_map: &HashMap<u8, Vec<u64>>, walls: &[[bool; 128]; 128], x: u64, y: u64, result: u64) -> Vec<String>
{
    let curresult = ((x as u64) << 16) | (y as u64);
    if curresult == result {
        return vec![String::from("")];
    }

    // for i in 0..128isize {
    //     for j in 0..128isize {
    //         if (i, j) == (x as isize, y as isize) {
    //             print!("o")
    //         } else if walls[i as usize][j as usize] {
    //             print!("#")
    //         } else {
    //             print!("{}", " ");
    //         }
    //     }
    //     println!()
    // }

    let mut possibilities = Vec::new();

    for (c, moves) in action_map {
        let mut curx = x;
        let mut cury = y;
        let mut is_valid = true;
        let mut walls_copy = walls.clone();
        walls_copy[curx as usize][cury as usize] = true;
        for mov in moves {
            match *mov {
                UR => {
                    curx += 1;
                    cury += 1;
                }
                U => { cury += 1 }
                UL => {
                    curx -= 1;
                    cury += 1;
                }
                L => { curx -= 1; }
                R => { curx += 1; }
                DR => {
                    curx += 1;
                    cury -= 1;
                }
                D => { cury -= 1; }
                DL => {
                    curx -= 1;
                    cury -= 1;
                }
                _ => unreachable!()
            }

            if curx >= 128 || curx < 0 || cury >= 128 || cury < 0 || walls_copy[curx as usize][cury as usize] {
                is_valid = false;
                break;
            }
            walls_copy[curx as usize][cury as usize] = true;
        }
        if (is_valid) {
            for solution in solve_maze_rec(action_map, &walls_copy, curx, cury, result) {
                possibilities.push(String::from(*c as char) + &*solution);
            }
        }
    }

    possibilities
}

pub fn solve(action_map: &HashMap<u8, Vec<u64>>, walls: &[[bool; 128]; 128], maze_result: u64, half_hash1: usize, half_hash2: usize, control1_string: [u8; 16], control2_string: [u8; 16], flag_hash_value: u32) {
    let candidate_solutions = solve_maze_rec(action_map, walls, 64, 64, maze_result);

    let mut solved = false;
    for candidate_solution in candidate_solutions {
        let candidate_half1 = candidate_solution[0..16].as_bytes();
        let candidate_half2 = candidate_solution[16..32].as_bytes();

        if half_hash(candidate_half1) != half_hash1 { continue; }
        if half_hash(candidate_half2) != half_hash2 { continue; }

        let unscrambled1 = pshufb_inverse(candidate_half1, control1_string.as_slice());
        let unscrambled2 = pshufb_inverse(candidate_half2, control2_string.as_slice());

        let full = String::from_utf8(unscrambled1).unwrap() + &String::from_utf8(unscrambled2).unwrap();
        let flag = format!("dice{{{full}}}");

        if flag_hash(flag.as_str()) != flag_hash_value { continue; };

        assert_eq!(flag, FLAG);
        println!("SOLVED: {}", flag);

        solved = true;
    }

    assert!(solved);
}