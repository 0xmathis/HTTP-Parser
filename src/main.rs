mod node;
mod parser;
mod parsing_error;
mod utils;

use parsing_error::ParsingError;
use parser::parser;
use node::Node;

use std::env;
use std::fs::File;
use std::io::{Read, Error};


fn read_file(filepath: &str) -> Result<Vec<u8>, Error> {
    let mut file = File::open(filepath)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    return Ok(content);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        panic!("usage: http-parser <file>");
    }

    let filepath: &String = args.get(1).unwrap();
    let content: Vec<u8>;
    let content_length: u8;

    if let Ok(m) = read_file(filepath) {
        content_length = m.len() as u8;
        content = m;
    } else {
        panic!("File problem");
    }

    let request_content: Box<Vec<u8>> = Box::new(content);
    let result: Result<Node, ParsingError> = parser(&request_content, content_length);

    match result {
        Ok(root) => root.print_as_root(&request_content),
        Err(e) => println!("{e}"),
    }
}
