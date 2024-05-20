use crate::node::Node;
use crate::parsing_error::ParsingError;
use crate::utils;


pub fn parser(http_request: &Box<Vec<u8>>, length: u8) -> Result<Node, ParsingError> {
    let mut root: Node = Node::empty();

    let result: Result<(), ParsingError> = detect_http_message(&mut root , http_request, 0);

    if root.get_length() > length {
        root.set_length(length);
    }

    match result {
        Ok(_) => { Ok(root) },
        Err(e) => { Err(e) },
    }
}

fn detect_http_message(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.init(String::from("HTTP_message"), index, 0);

    match detect_start_line(parent, http_request, index) {
        Ok(()) => index += parent.get_last_child().get_length(),
        Err(e) => return Err(ParsingError::new(String::from("No start line detected")) + e)
    }

    loop {
        if let Ok(()) = detect_header_field(parent, http_request, index) {
            index += parent.get_last_child().get_length();

            match detect_crlf(parent, http_request, index) {
                Ok(()) => index += parent.get_last_child().get_length(),
                Err(e) => return Err(ParsingError::new(String::from("No CRLF detected")) + e)
            }
        } else {
            break;
        }
    }

    match detect_crlf(parent, http_request, index) {
        Ok(()) => index += parent.get_last_child().get_length(),
        Err(e) => return Err(ParsingError::new(String::from("No CRLF detected")) + e)
    }

    let _ = detect_message_body(parent, http_request, index);

    parent.set_length(parent.get_sum_length_children());
    Ok(())
}

fn detect_start_line(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("start_line"), index, 0);

    if let Err(e) = detect_request_line(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No request line detected")) + e);
    } 

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_request_line(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("request_line"), index, 0);

    match detect_method(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No method detected")) + e);
        }
    }

    match detect_sp(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No SP detected")) + e);
        }
    }

    match detect_request_target(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No request target detected")) + e);
        }
    }

    match detect_sp(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No SP detected")) + e);
        }
    }

    match detect_http_version(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No HTTP version detected")) + e);
        }
    }

    match detect_crlf(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No CRLF detected")) + e);
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_header_field(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("header_field"), index, 0);

    if let Ok(()) = detect_connection_header(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_content_length_header(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_content_type_header(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_cookie_header(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_transfer_encoding_header(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_expect_header(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_host_header(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_user_agent_header(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_accept_language_header(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_accept_header(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_accept_encoding_header(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_field_name(node, http_request, index) {
        index += node.get_last_child().get_length();

        if utils::get_request_char(http_request, index as usize) == b':' {
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
        } else {
            return Err(ParsingError::new(String::from("No : detected")));
        }

        if let Ok(()) = detect_ows(node, http_request, index) {
            index += node.get_last_child().get_length();
        }

        return Err(ParsingError::new(String::from("Not implemented")));

        // if let Err(_) = detect_field_value(node, http_request, index) {
        //     parent.del_last_child();
        // }

        // if node.get_last_child().get_length() == 0 {
        //     node.del_last_child();
        // } else {
        //     index += node.get_last_child().get_length();
        // }

        // if let Ok(()) = detect_ows(node, http_request, index) {
        //     index += node.get_last_child().get_length();
        // }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No header field component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_field_value(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_ows(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("header_field"), index, 0);
    let mut count: u8 = 0;

    loop {
        if let Ok(()) = detect_sp(node, http_request, index) {
            index += node.get_last_child().get_length();
            count += 1;
        } else if let Ok(()) = detect_htab(node, http_request, index) {
            index += node.get_last_child().get_length();
            count += 1;
        } else {
            break;
        }
    }

    if count == 0 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No OWS component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_field_name(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_accept_encoding_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_accept_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_accept_language_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_user_agent_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("header_field"), index, 0);

    if utils::starts_with(b"User-Agent".to_vec(), http_request, index as usize) {
        node.add_child("case_insensitive_string".to_string(), index, 10);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No User Agent string detected")));
    }

    if utils::get_request_char(http_request, index as usize) == b':' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No : detected")));
    }

    if let Ok(()) = detect_ows(node, http_request, index) {
        index += node.get_last_child().get_length();
    }

    match detect_user_agent(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No User Agent detected")) + e); 
        }
    }

    if let Ok(()) = detect_ows(node, http_request, index) {
        index += node.get_last_child().get_length();
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_host_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_expect_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_transfer_encoding_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_cookie_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_content_type_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_content_length_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_connection_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_user_agent(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init("User_Agent".to_string(), index, 0);

    match detect_product(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No product detected")) + e);
        }
    }

    loop {
        if let Ok(()) = detect_rws(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else {
            break;
        }

        if let Ok(()) = detect_product(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else if let Ok(()) = detect_comment(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else {
            node.del_last_child();
            break;
        }
    }

    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_product(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_rws(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_comment(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_crlf(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    if utils::starts_with(b"\r\n".to_vec(), http_request, index as usize) {
        parent.add_child(String::from("__crlf"), index, 2);
    } else {
        return Err(ParsingError::new(String::from("No \\r\\n detected")))
    }

    Ok(())
}

fn detect_message_body(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_method(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("method"), index, 0);

    if let Err(e) = detect_token(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No token detected")) + e);
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_token(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("token"), index, 0);
    let mut count: u8 = 0;

    loop {
        if let Ok(()) = detect_tchar(node, http_request, index) {
            index += node.get_last_child().get_length();
            count += 1;
        } else {
            break;
        }
    }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No tchar detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}


fn detect_tchar(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("tchar"), index, 0);

    if utils::is_in(utils::get_request_char(http_request, index as usize), b"!#$%&'*+-.^_`|~".to_vec()) {
        node.add_child("case_insensitive_string".to_string(), index, 1);
    } else if let Ok(()) = detect_digit(node, http_request, index) {
        node.add_child("__digit".to_string(), index, 1);
    } else if let Ok(()) = detect_alpha(node, http_request, index) {
        node.add_child("__alpha".to_string(), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No tchar component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_alpha(node: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    let c: u8 = utils::get_request_char(http_request, index as usize);

    if (0x41 <= c && c <= 0x5A) || (0x61 <= c && c <= 0x7A) {
        Ok(())
    } else {
        Err(ParsingError::new(String::from("No alpha detected")))
    }
}

fn detect_digit(node: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    let c: u8 = utils::get_request_char(http_request, index as usize);

    if 0x30 <= c && c <= 0x39 {
        Ok(())
    } else {
        Err(ParsingError::new(String::from("No digit detected")))
    }
}

fn detect_request_target(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("request_target"), index, 0);

    if let Err(e) = detect_origin_form(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No origin form detected")) + e);
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_origin_form(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("request_target"), index, 0);

    match detect_absolute_path(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No absolute path detected")) + e);
        }
    }

    if utils::get_request_char(http_request, index as usize) == b'?' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();


        if let Err(e) = detect_query(node, http_request, index) {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No query detected")) + e);
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_query(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_absolute_path(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("absolute_path"), index, 0);
    let mut count: u8 = 0;

    loop {
        if utils::get_request_char(http_request, index as usize) == b'/' {
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
        } else {
            break;
        }

        if utils::get_request_char(http_request, index as usize) == b'?' {
            if let Ok(()) = detect_segment(node, http_request, index) {
                index += node.get_last_child().get_length();
            }
        }

        count += 1;
    }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No absolute path detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_segment(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_http_version(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("HTTP_version"), index, 0);

    match detect_http_name(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => return Err(ParsingError::new(String::from("No HTTP name detected")) + e),
    }

    if utils::get_request_char(http_request, index as usize) == b'/' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        return Err(ParsingError::new(String::from("No / detected")));
    }

    if let Ok(()) = detect_digit(node, http_request, index) {
        node.add_child("__digit".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        return Err(ParsingError::new(String::from("No digit detected")));
    }

    if utils::get_request_char(http_request, index as usize) == b'.' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        return Err(ParsingError::new(String::from("No . detected")));
    }

    if let Ok(()) = detect_digit(node, http_request, index) {
        node.add_child("__digit".to_string(), index, 1);
    } else {
        return Err(ParsingError::new(String::from("No digit detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_http_name(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("HTTP_name"), index, 0);

    if utils::starts_with(b"HTTP".to_vec(), http_request, index as usize) {
        node.add_child("__num".to_string(), index, 4);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No HTTP name component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_sp(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    if http_request[index as usize] == b' ' {
        parent.add_child(String::from("__sp"), index, 1);
    } else {
        return Err(ParsingError::new(String::from("No space detected")))
    }

    Ok(())
}

fn detect_htab(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    if http_request[index as usize] == b'\t' {
        parent.add_child(String::from("__htab"), index, 1);
    } else {
        return Err(ParsingError::new(String::from("No htab detected")))
    }

    Ok(())
}
