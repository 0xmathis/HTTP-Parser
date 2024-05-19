use crate::node::Node;
use crate::parsing_error::ParsingError;


pub fn parser(content: Vec<u8>, length: u8) -> Result<Node, ParsingError> {
    let mut root: Node = Node::empty(Box::new(content));

    let result: Result<(), ParsingError> = detect_http_message(&mut root, 0);

    if root.get_length() > length {
        root.set_length(length);
    }

    match result {
        Ok(_) => { Ok(root) },
        Err(e) => { Err(e) },
    }
}

fn detect_http_message(parent: &mut Node, index: u8) -> Result<(), ParsingError> {
    parent.init(String::from("HTTP_message"), index, 0);
    Ok(())
}
