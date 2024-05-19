use std::fmt;


#[derive(Debug, Clone)]
pub struct ParsingError {
    message: String
}

impl ParsingError {
    pub fn new(message: String) -> Self {
        ParsingError {
            message
        }
    }
}

impl fmt::Display for ParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Parsing error {{ message: {} }}", self.message)
    }
}
