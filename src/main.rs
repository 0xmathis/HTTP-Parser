mod node;
mod parser;
mod parsing_error;
mod utils;

use parsing_error::ParsingError;
use parser::parser;
use node::Node;

use std::fs::File;
use std::io::{Error, Read, Write};
use clap::Parser;
use serde_json::{self, Value};

// https://blog.logrocket.com/command-line-argument-parsing-rust-using-clap/
/// HTTP Parser
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// File to parse
    filepath: String,

    /// File to store to JSON
    #[arg(long)]
    json_path: Option<String>,
}

// TODO: Enable user to store parsing tree in JSON file

fn read_file(filepath: &str) -> Result<Vec<u8>, Error> {
    let mut file: File = File::open(filepath)?;
    let mut content: Vec<u8> = Vec::new();
    file.read_to_end(&mut content)?;

    return Ok(content);
}

fn write_json_file(filepath: &str, json: Value) -> () {
    let mut file: File = File::create(filepath).expect("File problem");
    let json_vec: Vec<u8> = serde_json::to_vec(&json).expect("Error parsing JSON");
    file.write(&json_vec).expect("Error writing JSON");
}

fn main() {
    let args = Args::parse();

    let filepath: String = args.filepath;
    let json_path: Option<String> = args.json_path;
    let content: Vec<u8>;
    let content_length: usize;

    if let Ok(m) = read_file(&filepath) {
        content_length = m.len();
        content = m;
    } else {
        panic!("File problem");
    }

    let request_content: Box<Vec<u8>> = Box::new(content);
    let result: Result<Node, ParsingError> = parser(&request_content, content_length);

    match result {
        Ok(root) => {
            match json_path {
            Some(path) => {
                let json_value: Value = root.dump_to_json(&request_content);
                write_json_file(&path, json_value);
            },
            None => root.print_as_root(&request_content),
            }
        }
        Err(e) => {
            eprintln!("{e}");
            println!("NOK");
        }
    }
}
