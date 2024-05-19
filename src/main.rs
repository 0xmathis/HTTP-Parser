mod node;
use node::Node;

fn main() {
    let file: String = "Hello World!".to_string();
    let mut node: Node = Node::new(Box::new(file), "label1".to_string(), 0u16, 12u16);
    node.add_child("label2".to_string(), 0u16, 5u16);
    node.add_child("label3".to_string(), 5u16, 7u16);

    println!("{:?}", node);
    node.print_as_root();

    let string: String = "Hello World!".to_string();
    let pointer: Box<String> = Box::new(string);

    println!("{}", *pointer);
}
