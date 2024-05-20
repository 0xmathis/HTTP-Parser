use crate::utils;

#[derive(Debug)]
#[derive(Clone)]
#[derive(PartialEq)]
pub struct Node {
    label: String,
    start: u8,
    length: u8,
    children: Vec<Self>,
}

impl Node {
    pub fn new(label: String, start: u8, length: u8) -> Self {
        Self {
            label,
            start,
            length,
            children: Vec::new(),
        }
    }

    pub fn empty() -> Self {
        Self {
            label: String::new(),
            start: 0,
            length: 0,
            children: Vec::new(),
        }
    }

    pub fn init(&mut self, label: String, start: u8, length: u8) -> () { 
        self.set_label(label);
        self.set_start(start);
        self.set_length(length);
    }

    pub fn add_child(&mut self, label: String, start: u8, length: u8) -> () {
        let child: Self = Self::new(label, start, length);
        self.children.push(child);
    }

    pub fn add_empty_child(&mut self) -> () {
        let child: Self = Self::empty();
        self.children.push(child);
    }

    // Destructors
    
    pub fn del(&mut self) -> () {
        let children: &mut Vec<Node> = self.get_mut_children();
        
        while children.len() > 0 {
            children.pop().unwrap().del();
        }
    }

    pub fn del_last_child(&mut self) -> () {
        self.get_mut_children().pop().unwrap().del();
    }

    // Setters
    
    pub fn set_label(&mut self, label: String) -> () {
        self.label = label;
    }
    
    pub fn set_start(&mut self, start: u8) -> () {
        self.start = start;
    }
    
    pub fn set_length(&mut self, length: u8) -> () {
        self.length = length;
    }
    
    // Getters

    pub fn get_label(&self) -> &String {
        return &self.label;
    }

    pub fn get_start(&self) -> u8 {
        return self.start;
    }

    pub fn get_length(&self) -> u8 {
        return self.length;
    }

    pub fn get_children(&self) -> &Vec<Self> {
        return &self.children;
    }

    pub fn get_mut_children(&mut self) -> &mut Vec<Self> {
        return &mut self.children;
    }

    pub fn get_mut_child(&mut self) -> &mut Vec<Self> {
        return &mut self.children;
    }

    pub fn get_last_child(&self) -> &Self {
        let len: usize = self.children.len();

        return &self.children[len - 1];
    }

    pub fn get_mut_last_child(&mut self) -> &mut Self {
        let len: usize = self.children.len();

        return &mut self.children[len - 1];
    }

    pub fn get_sum_length_children(&self) -> u8 {
        let mut sum: u8 = 0;

        for child in self.children.iter() {
            sum += child.get_length();
        }

        sum
    }

    pub fn print_as_root(&self, request_content: &Box<Vec<u8>>) -> () {
        self.print(request_content, 0);
    }

    fn print(&self, request_content: &Box<Vec<u8>>, depth: u16) -> () {
        for _ in 0..4*depth {
            print!(" ");
        }

        print!("[{}:{}] = \"", depth, self.get_label());

        if self.get_label() == "__crlf" {
            print!("__");
        } else if self.get_length() > 9 {
            for i in 0..3 {
                let c: u8 = utils::get_request_char(request_content, (self.get_start() + i) as usize);

                if c == b'\r' || c == b'\n' {
                    print!("_");
                } else {
                    print!("{}", c as char);
                }
            }

            print!("..");
        } else {
            for i in 0..self.get_length() {
                let c: u8 = utils::get_request_char(request_content, (self.get_start() + i) as usize);

                if c == b'\r' || c == b'\n' {
                    print!("_");
                } else {
                    print!("{}", c as char);
                }
            }
        }

        print!("\"\n");

        for child in self.children.iter() {
            child.print(request_content, depth + 1)
        }
    }
}

