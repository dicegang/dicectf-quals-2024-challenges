use std::error::Error;

use lexpr::parse::Options;
use lexpr::Value;

use crate::parse::Ast::{Apply, Identifier, Let, Number};
use crate::parse::Operation::{Add, Concat, EvaluateX86, Exit, GetFlag, If, Multiply, Substring, UserDefined};

#[derive(Debug, Clone)]
pub enum Operation {
    Add(),
    Multiply(),
    Substring(),
    Concat(),
    Exit(),
    GetFlag(),
    If(),
    EvaluateX86(),
    UserDefined { name: String },
}

#[derive(Debug, Clone)]
pub enum Ast {
    Apply {
        op: Operation,
        args: Vec<Box<Ast>>,
    },
    Identifier {
        name: String,
    },
    Let {
        var_name: String,
        value: Box<Ast>,
        body: Box<Ast>,
    },
    Number(u64),
    String(String),
}

#[derive(Debug)]
pub struct Definition {
    pub name: String,
    pub args: Vec<String>,
    pub body: Ast,
}

#[derive(Debug)]
pub struct Program {
    pub definitions: Vec<Definition>,
}

fn parse_operation(name: String) -> Operation {
    match name.as_str() {
        "+" => Add(),
        "*" => Multiply(),
        "substr" => Substring(),
        "concat" => Concat(),
        "get_flag" => GetFlag(),
        "evaluate" => EvaluateX86(),
        "exit" => Exit(),
        "if" => If(),
        _ => UserDefined { name },
    }
}

fn parse(source: &Value) -> Result<Ast, Box<dyn Error>> {
    match source {
        Value::Symbol(str) => Ok(Identifier {
            name: str.to_string(),
        }),
        Value::Number(x) => Ok(Number(x.as_u64().unwrap())),
        Value::String(x) => Ok(Ast::String(x.clone().into_string())),
        Value::Bytes(x) => Ok(Ast::String(String::from_utf8((*x).to_vec()).unwrap())),
        Value::Cons(cons) => match cons.clone().into_vec().0.as_slice() {
            [Value::Symbol(keyword), ..] if keyword.to_string() == "seq!" => {
                let clone = cons.clone().into_vec().0;

                let mut exprs = vec![];
                for i in 1..clone.len() {
                    exprs.push(parse(&clone[i]).unwrap())
                }

                let mut base = exprs.last().unwrap().clone();
                for expr in exprs.iter().rev().skip(1) {
                    base = Let {
                        var_name: "_internal_accumulator_seq".to_string(),
                        body: Box::from(base),
                        value: Box::from(expr.clone()),
                    };
                }
                Ok(base)
            }
            [Value::Symbol(keyword), count, initial, accumulator, ..]
                if keyword.to_string() == "seqfoldl!" =>
            {
                let count_int = count.as_u64().unwrap();

                let mut base = Identifier {
                    name: "_internal_accumulator".to_string(),
                };

                let clone = cons.clone().into_vec().0;
                let mut additional_args = vec![];
                for i in 4..clone.len() {
                    additional_args.push(Box::from(Identifier {
                        name: clone.get(i).unwrap().as_symbol().unwrap().to_string(),
                    }))
                }

                for i in (0..count_int).rev() {
                    let mut args = vec![
                        Box::from(Identifier {
                            name: "_internal_accumulator".to_string(),
                        }),
                        Box::from(Number(i)),
                    ];
                    args.extend(additional_args.clone());
                    base = Let {
                        var_name: "_internal_accumulator".to_string(),
                        value: Box::from(Apply {
                            op: parse_operation(accumulator.as_symbol().unwrap().to_string()),
                            args,
                        }),
                        body: Box::from(base),
                    }
                }
                Ok(Let {
                    var_name: "_internal_accumulator".to_string(),
                    value: Box::from(parse(initial)?),
                    body: Box::from(base),
                })
            }
            [Value::Symbol(op), Value::Cons(cons), body] if op.to_string() == "let" => {
                let name = cons.car().as_symbol().unwrap().to_string();
                let val = cons.cdr().as_cons().unwrap().car();

                Ok(Let {
                    var_name: name,
                    value: Box::new(parse(val)?),
                    body: Box::new(parse(body)?),
                })
            }
            _ => {
                let apply = cons.clone().into_vec().0;
                Ok(Apply {
                    op: parse_operation(apply[0].to_string()),
                    args: apply[1..]
                        .iter()
                        .map(|v| Box::new(parse(v).unwrap()))
                        .collect(),
                })
            }
        },
        _ => unreachable!(),
    }
}

pub fn parse_program(data: &str) -> Program {
    let mut definitions = vec![];

    for x in lexpr::Parser::from_str_custom(data, Options::elisp())
        .next_value()
        .unwrap()
        .unwrap()
        .as_cons()
        .unwrap()
        .clone()
        .into_vec()
        .0
    {
        match x {
            Value::Cons(cons) => match cons.clone().into_vec().0.as_slice() {
                [Value::Symbol(keyword), args, body] if keyword.as_ref() == "define" => {
                    let mut args_vec = vec![];
                    let mut name = String::new();
                    for (i, arg) in args.as_cons().unwrap().list_iter().enumerate() {
                        if i == 0 {
                            name = arg.to_string();
                        } else {
                            args_vec.push(arg.as_symbol().unwrap().to_string());
                        }
                    }
                    let body = parse(body).unwrap();
                    definitions.push(Definition {
                        name,
                        args: args_vec,
                        body,
                    })
                }
                y => {
                    eprintln!("{:?}", y);
                    unreachable!()
                }
            },
            _ => unreachable!(),
        }
    }

    Program { definitions }
}
