pub fn starts_with(start: Vec<u8>, content: &Box<Vec<u8>>, index: usize) -> bool {
    for i in 0..start.len() {
        if start.get(i) != content.get(index + i) {
            return false;
        }
    }

    true
}

pub fn is_in(c: u8, content: Vec<u8>) -> bool {
    if let Some(_) = content.iter().position(|&x| x == c) {
        return true;
    }

    false
}

pub fn get_request_char(http_request: &Box<Vec<u8>>, index: usize) -> u8 {
    match (*http_request).get(index) {
        Some(i) => return *i,
        None => return 0,
    }
}
