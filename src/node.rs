#[derive(Debug, Clone)]
pub struct Node {
    http_request: Box<String>,
    label: String,
    start: u16,
    length: u16,
    children: Vec<Self>,
}

impl Node {
    pub fn new(http_request: Box<String>, label: String, start: u16, length: u16) -> Self {
        Self {
            http_request,
            label,
            start,
            length,
            children: Vec::new(),
        }
    }

    pub fn add_child(&mut self, label: String, start: u16, length: u16) -> () {
        let child: Self = Self::new(self.http_request.clone(), label, start, length);
        self.children.push(child);
    }

    // Setters
    
    pub fn set_label(&mut self, label: &str) -> () {
        self.label = label.to_string();
    }
    
    pub fn set_start(&mut self, start: u16) -> () {
        self.start = start;
    }
    
    pub fn set_length(&mut self, length: u16) -> () {
        self.length = length;
    }
    
    // Getters
    
    pub fn get_char(&self, index: u16) -> char {
        (*self.http_request).chars().nth(index.into()).unwrap()
    }

    pub fn get_label(&self) -> &String {
        return &self.label;
    }

    pub fn get_start(&self) -> u16 {
        return self.start;
    }

    pub fn get_length(&self) -> u16 {
        return self.length;
    }

    pub fn get_child(&self) -> &Vec<Self> {
        return &self.children;
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

    pub fn print_as_root(&self) -> () {
        self.print(0);
    }

    fn print(&self, depth: u16) -> () {
        for _ in 0..4*depth {
            print!(" ");
        }

        print!("[{}:{}] = \"", depth, self.get_label());

        if self.get_label() == "__crlf" {
            print!("__");
        } else if self.get_length() > 9 {
            for i in 0..3 {
                let c: char = self.get_char(self.get_start() + i);

                if c == '\r' || c == '\n' {
                    print!("_");
                } else {
                    print!("{}", c);
                }
            }

            print!("..");
        } else {
            for i in 0..self.get_length() {
                let c: char = self.get_char(self.get_start() + i);

                if c == '\r' || c == '\n' {
                    print!("_");
                } else {
                    print!("{}", c);
                }
            }
        }

        print!("\"\n");

        for child in self.children.iter() {
            child.print(depth + 1)
        }
    }
}

