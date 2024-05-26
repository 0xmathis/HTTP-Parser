use std::fmt::{
    Display,
    Formatter,
    Result,
};
use std::ops::Add;


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

impl Display for ParsingError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Parsing error {{ {} }}", self.message)
    }
}

impl Add for ParsingError {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            message: self.message + " | " + &other.message
        }
    }
}
