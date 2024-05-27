use crate::node::Node;
use crate::parsing_error::ParsingError;
use crate::utils;


pub fn parser(http_request: &Box<Vec<u8>>, length: u8) -> Result<Node, ParsingError> {
    let mut root: Node = Node::empty();

    let result: Result<(), ParsingError> = detect_http_message(&mut root , http_request, 0);

    if root.get_length() > length {
        root.set_length(length);
    }

    root.print_as_root(http_request);
        
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
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No ':' detected")));
        }

        if let Ok(()) = detect_ows(node, http_request, index) {
            index += node.get_last_child().get_length();
        }

        if let Err(e) = detect_field_value(node, http_request, index) {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No field value detected")) + e);
        }

        if node.get_last_child().get_length() == 0 {
            node.del_last_child();
        } else {
            index += node.get_last_child().get_length();
        }

        if let Ok(()) = detect_ows(node, http_request, index) {
            index += node.get_last_child().get_length();
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No header field component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_field_value(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("field_value"), index, 0);
    let mut count: u8 = 0;

    loop {
        if let Ok(()) = detect_field_content(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else if let Ok(()) = detect_obs_fold(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else {
            break;
        }

        count += 1;
    }

    if count == 0 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No field value component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_obs_fold(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("header_field"), index, 0);
    let mut count: u8 = 0;

    match detect_crlf(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No CRLF detected")) + e);
        }
    }

    loop {
        if let Ok(()) = detect_sp(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else if let Ok(()) = detect_htab(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else {
            break;
        }

        count += 1;
    }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No obs fold component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_field_content(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    todo!()
}

fn detect_ows(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("OWS"), index, 0);
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
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("header_field"), index, 0);

    match detect_token(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No token detected")) + e); 
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_accept_encoding_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("Accept Encodings header"), index, 0);

    if utils::starts_with(b"Accept Encoding".to_vec(), http_request, index as usize) {
        node.add_child("case_insensitive_string".to_string(), index, 15);
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

    match detect_accept_encoding(node, http_request, index) {
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

fn detect_accept_encoding(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("Accept_Encoding"), index, 0);

    if utils::get_request_char(http_request, index as usize) == b',' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_codings(node, http_request, index) {
        index += node.get_last_child().get_length();

        if let Ok(()) = detect_weight(node, http_request, index) {
            index += node.get_last_child().get_length();
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No accept encodings component detected")));
    }

    todo!();

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_weight(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("weight"), index, 0);

    match detect_ows(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No OWS detected")) + e);
        }
    }

    if utils::get_request_char(http_request, index as usize) == b';' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No ';' detected")));
    }

    match detect_ows(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No OWS detected")) + e);
        }
    }

    if utils::starts_with(b"q=".to_vec(), http_request, index as usize) {
        node.add_child("case_insensitive_string".to_string(), index, 2);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No \"q=\" detected")));
    }

    match detect_qvalue(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No qvalue detected")) + e);
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_qvalue(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("qvalue"), index, 0);
    let mut c: u8 = utils::get_request_char(http_request, index as usize);

    if c == b'0' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
        c = utils::get_request_char(http_request, index as usize);

        if c == b'.' {
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
            let mut count: u8 = 0;

            loop {
                match detect_digit(node, http_request, index) {
                    Ok(()) => {
                        node.add_child("__digit".to_string(), index, 1);
                        index += node.get_last_child().get_length();
                    }
                    Err(_) => break,
                }

                count += 1;
            }

            if count > 3 {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No qvalue component detected")));
            }
        }
    } else if c == b'1' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
        c = utils::get_request_char(http_request, index as usize);

        if c == b'.' {
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
            let mut count: u8 = 0;
            c = utils::get_request_char(http_request, index as usize);

            loop {
                if c == b'0' {
                    node.add_child("__digit".to_string(), index, 1);
                    index += node.get_last_child().get_length();
                } else {
                    break;
                }

                count += 1;
            }

            if count > 3 {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No qvalue component detected")));
            }
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No qvalue component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_codings(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("codings"), index, 0);

    if let Ok(()) = detect_content_codings(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if utils::starts_with(b"identity".to_vec(), http_request, index as usize) {
        node.add_child("case_insensitive_string".to_string(), index, 8);
        index += node.get_last_child().get_length();
    } else if utils::get_request_char(http_request, index as usize) == b'*' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No codings component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_content_codings(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("content codings"), index, 0);

    if let Err(e) = detect_token(node, http_request, index) {
        return Err(ParsingError::new(String::from("No token detected")) + e);
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_accept_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("Accept header"), index, 0);

    if utils::starts_with(b"Accept".to_vec(), http_request, index as usize) {
        node.add_child("case_insensitive_string".to_string(), index, 6);
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

    match detect_accept(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No Accept detected")) + e); 
        }
    }

    if let Ok(()) = detect_ows(node, http_request, index) {
        index += node.get_last_child().get_length();
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_accept(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("accept"), index, 0);

    if utils::get_request_char(http_request, index as usize) == b',' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_media_range(node, http_request, index) {
        index += node.get_last_child().get_length();

        if let Ok(()) = detect_accept_params(node, http_request, index) {
            index += node.get_last_child().get_length();
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No accept component detected")));
    }

    loop {
        if detect_ows(node, http_request, index) == Ok(()) && utils::get_request_char(http_request, (index + node.get_last_child().get_length()) as usize) == b',' {
            index += node.get_last_child().get_length();
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
        } else if utils::get_request_char(http_request, index as usize) == b',' {
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
        } else {
            if node.get_last_child().get_label() == "OWS" {
                node.del_last_child();
            }

            break;
        }

        if let Ok(()) = detect_ows(node, http_request, index) {
            index += node.get_last_child().get_length();
        }

        if let Ok(()) = detect_media_range(node, http_request, index) {
            index += node.get_last_child().get_length();

            if let Ok(()) = detect_accept_params(node, http_request, index) {
                index += node.get_last_child().get_length();
            }
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_accept_params(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("accept_params"), index, 0);

    match detect_weight(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No weight detected")) + e);
        }
    }

    loop {
        match detect_accept_ext(node, http_request, index) {
            Ok(()) => index += node.get_last_child().get_length(),
            Err(_) => {
                break;
            }
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_accept_ext(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("media_range"), index, 0);

    if detect_ows(node, http_request, index) == Ok(()) && utils::get_request_char(http_request, (index + node.get_last_child().get_length()) as usize) == b';' {
        index += node.get_last_child().get_length();
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else if utils::get_request_char(http_request, index as usize) == b';' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No accept ext component detected")));
    }

    if let Ok(()) = detect_ows(node, http_request, index) {
        index += node.get_last_child().get_length();
    }

    match detect_token(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No token detected")) + e);
        }
    }

    if utils::get_request_char(http_request, index as usize) == b'='  {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();

        if let Ok(()) = detect_token(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else if let Ok(()) = detect_token(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No accept ext component detected")));
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_media_range(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("media_range"), index, 0);

    if utils::starts_with(b"*/*".to_vec(), http_request, index as usize) {
        node.add_child("case_insensitive_string".to_string(), index, 3);
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_type(node, http_request, index) {
        index += node.get_last_child().get_length();

        if utils::get_request_char(http_request, index as usize) == b'/' {
            index += node.get_last_child().get_length();
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No '/' detected")));
        }

        match detect_subtype(node, http_request, index) {
            Ok(()) => index += node.get_last_child().get_length(),
            Err(e) => {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No subtype detected")) + e);
            }
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No media range component detected")));
    }

    loop {
        if detect_ows(node, http_request, index) == Ok(()) && utils::get_request_char(http_request, (index + node.get_last_child().get_length()) as usize) == b',' {
            index += node.get_last_child().get_length();
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
        } else if utils::get_request_char(http_request, index as usize) == b',' {
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
        } else {
            if node.get_last_child().get_label() == "OWS" {
                node.del_last_child();
            }

            break;
        }

        if let Ok(()) = detect_ows(node, http_request, index) {
            index += node.get_last_child().get_length();
        }

        match detect_parameter(node, http_request, index) {
            Ok(()) => index += node.get_last_child().get_length(),
            Err(e) => {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No parameter detected")) + e);
            }
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_parameter(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    todo!()
}

fn detect_type(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("type"), index, 0);

    match detect_token(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No token detected")) + e);
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_subtype(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("subtype"), index, 0);

    match detect_token(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No token detected")) + e);
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_accept_language_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    return Err(ParsingError::new(String::from("Not implemented")));
}

fn detect_user_agent_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("User Agent header"), index, 0);

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
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("Host header"), index, 0);

    if utils::starts_with(b"Host".to_vec(), http_request, index as usize) {
        node.add_child("case_insensitive_string".to_string(), index, 4);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Host string detected")));
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

    if let Ok(()) = detect_host(node, http_request, index) {
        index += node.get_last_child().get_length();

        if node.get_last_child().get_length() == 0 {
            node.del_last_child();
        } else {
            index += node.get_last_child().get_length();
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No User Agent detected"))); 
    }

    if let Ok(()) = detect_ows(node, http_request, index) {
        index += node.get_last_child().get_length();
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_host(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("Host"), index, 0);

    match detect_uri_host(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No uri host detected")) + e); 
        }
    }

    if utils::get_request_char(http_request, index as usize) == b':' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();

        match detect_port(node, http_request, index) {
            Ok(()) => index += node.get_last_child().get_length(),
            Err(e) => {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No port detected")) + e); 
            }
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_uri_host(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("uri_host"), index, 0);
    
    match detect_host_(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No host detected")) + e); 
        }
    }

    if node.get_sum_length_children() == 0 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No uri host detected"))); 
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_host_(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("host"), index, 0);

    if let Ok(()) = detect_ip_literal(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_ipv4address(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_reg_name(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No host component detected"))); 
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_reg_name(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("host"), index, 0);
    let mut count: u8 = 0;

    loop {
        if let Ok(()) = detect_unreserved(node, http_request, index) {
            index += node.get_last_child().get_length();
            count += 1;
        } else if let Ok(()) = detect_pct_encoded(node, http_request, index) {
            index += node.get_last_child().get_length();
            count += 1;
        } else if let Ok(()) = detect_sub_delims(node, http_request, index) {
            index += node.get_last_child().get_length();
            count += 1;
        } else {
            break;
        }
    }

    if count == 0 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No reg name component detected"))); 
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_ipv4address(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("IPv4address"), index, 0);

    for _ in 0..3 {
        match detect_dec_octet(node, http_request, index) {
            Ok(()) => index += node.get_last_child().get_length(),
            Err(e) => {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No reg name component detected")) + e);
            }
        }

        if utils::get_request_char(http_request, index as usize) == b'.' {
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No reg name component detected")));
        }
    }

    match detect_dec_octet(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No reg name component detected")) + e);
        }
    }


    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_dec_octet(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("dec_octet"), index, 0);
    let c0: u8 = utils::get_request_char(http_request, index as usize);
    let c1: u8 = utils::get_request_char(http_request, (index + 1) as usize);
    let c2: u8 = utils::get_request_char(http_request, (index + 2) as usize);

    if c0 == b'2' && c1 == b'5' && b'0' <= c2 && c2 <= b'5' {
        node.add_child("case_insensitive_string".to_string(), index, 2);
        node.add_child("__digit".to_string(), index, 1);
    } else if c0 == b'2' && b'0' <= c1 && c1 <= b'4' && detect_digit(node, http_request, index + 2) == Ok(()) {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        node.add_child("__range".to_string(), index + 1, 1);
        node.add_child("__digit".to_string(), index + 2, 1);
    } else if c0 == b'1' && detect_digit(node, http_request, index + 1) == Ok(()) && detect_digit(node, http_request, index + 2) == Ok(()) {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        node.add_child("__digit".to_string(), index + 1, 1);
        node.add_child("__digit".to_string(), index + 1, 1);
    } else if  b'1' <= c0 && c0 <= b'9' && detect_digit(node, http_request, index + 1) == Ok(()) {
        node.add_child("__range".to_string(), index, 1);
        node.add_child("__digit".to_string(), index, 1);
    } else if  detect_digit(node, http_request, index) == Ok(()) {
        node.add_child("__digit".to_string(), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No dec octet detected"))); 
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_ip_literal(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("dec_octet"), index, 0);

    if utils::get_request_char(http_request, index as usize) == b'[' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '[' detected"))); 
    }

    if let Ok(()) = detect_ipv6address(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_ipvfuture(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No ip literal component detected"))); 
    }

    if utils::get_request_char(http_request, index as usize) == b']' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No ']' detected"))); 
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_ipvfuture(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("IPvFuture"), index, 0);
    let mut count: u8;
    let c: u8 = utils::get_request_char(http_request, index as usize);

    if c == b'v' || c == b'V' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '[' detected"))); 
    }

    count = 0;

    loop {
        match detect_hexdig(node, http_request, index) {
            Ok(()) => index += node.get_last_child().get_length(),
            Err(_) => break
        }

        count += 1;
    }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No ipvfuture component detected"))); 
    }

    count = 0;

    loop {
        if let Ok(()) = detect_unreserved(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else if let Ok(()) = detect_sub_delims(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else if utils::get_request_char(http_request, index as usize) == b':' {
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
        } else {
            break;
        }

        count += 1;
    }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No ipvfuture component detected"))); 
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_ipv6address(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("IPv6address"), index, 0);
    let mut count: u8 = 0;

    loop {
        if count == 6 {
            break;
        }

        match detect_h16(node, http_request, index) {
            Ok(()) => index += node.get_last_child().get_length(),
            Err(_) => break
        }

        count += 1;

        if utils::starts_with(b"::".to_vec(), http_request, index as usize) {
            break;
        }

        if utils::get_request_char(http_request, index as usize) == b':' {
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No ipv6address component detected"))); 
        }
    }

    if count == 6 {
        if let Ok(()) = detect_ls32(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else if let Ok(()) = detect_h16(node, http_request, index) {
            index += node.get_last_child().get_length();

            if utils::starts_with(b"::".to_vec(), http_request, index as usize) {
                node.add_child("case_insensitive_string".to_string(), index, 2);
                index += node.get_last_child().get_length();
            } else {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No ipv6address component detected"))); 
            }
        } else if utils::starts_with(b"::".to_vec(), http_request, index as usize) {
            node.add_child("case_insensitive_string".to_string(), index, 2);
            index += node.get_last_child().get_length();

            if let Ok(()) = detect_h16(node, http_request, index) {
                index += node.get_last_child().get_length();
            }
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No ipv6address component detected"))); 
        }
    } else if utils::starts_with(b"::".to_vec(), http_request, index as usize) {
        node.add_child("case_insensitive_string".to_string(), index, 2);
        index += node.get_last_child().get_length();

        loop {
            if detect_ls32(node, http_request, index) == Ok(()) && utils::get_request_char(http_request, (index + node.get_last_child().get_length()) as usize) == b']' {
                if count > 5 {
                    parent.del_last_child();
                    return Err(ParsingError::new(String::from("No ipv6address component detected"))); 
                }

                index += node.get_last_child().get_length();
                break
            } else if node.get_last_child().get_label() == "ls32" {
                node.del_last_child();
            }

            if let Ok(()) = detect_h16(node, http_request, index) {
                index += node.get_last_child().get_length();
                count += 1;

                if utils::get_request_char(http_request, index as usize) == b']' {
                    break;
                }
            } else {
                break;
            }

            if utils::get_request_char(http_request, index as usize) == b':' {
                node.add_child("case_insensitive_string".to_string(), index, 1);
                index += node.get_last_child().get_length();
            } else {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No ipv6address component detected"))); 
            }
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_h16(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("h16"), index, 0);
    let mut count: u8 = 0;

    loop {
        match detect_hexdig(node, http_request, index) {
            Ok(()) => {
                index += node.get_last_child().get_length();
                count += 1;

            }
            Err(_) => break
        }
    }

    if count < 1 || 4 < count {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No h16 component detected"))); 
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_ls32(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("ls32"), index, 0);

    if  let Ok(()) = detect_ipv4address(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_h16(node, http_request, index) {
        index += node.get_last_child().get_length();

        if utils::get_request_char(http_request, index as usize) == b':' {
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();

            if let Ok(()) = detect_h16(node, http_request, index) {
                index += node.get_last_child().get_length();
            } else {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No port detected"))); 
            }
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No port detected"))); 
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No port detected"))); 
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_port(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("port"), index, 0);
    let mut count: u8 = 0;

    loop {
        match detect_digit(node, http_request, index) {
            Ok(()) => {
                node.add_child("__digit".to_string(), index, 1);
                index += node.get_last_child().get_length();
                count += 1;

            }
            Err(_) => break
        }
    }

    if count == 0 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No port detected"))); 
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
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
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("Connection header"), index, 0);

    if utils::starts_with(b"Connection".to_vec(), http_request, index as usize) {
        node.add_child("case_insensitive_string".to_string(), index, 10);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Connection string detected")));
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

    match detect_connection(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No Connection detected")) + e); 
        }
    }

    if let Ok(()) = detect_ows(node, http_request, index) {
        index += node.get_last_child().get_length();
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_connection(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init("Connection".to_string(), index, 0);

    loop {
        if utils::get_request_char(http_request, index as usize) == b',' {
            node.add_child("case_insensitive_string".to_string(), index, 1);
            index += node.get_last_child().get_length();
        } else {
            break;
        }

        if let Ok(()) = detect_ows(node, http_request, index) {
            index += node.get_last_child().get_length();
        }
    }

    match detect_connection_option(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No connection option detected")) + e);
        }
    }

    loop {
        todo!();
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_connection_option(node: &mut Node, http_request: &Vec<u8, Global>, index: u8) -> Result<(), ParsingError> {
    todo!()
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

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_product(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init("product".to_string(), index, 0);

    match detect_token(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No token detected")) + e)
        }
    }

    if utils::get_request_char(http_request, index as usize) == b'/' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();

        match detect_product_version(node, http_request, index) {
            Ok(()) => index += node.get_last_child().get_length(),
            Err(e) => {
                node.del_last_child();
                return Err(ParsingError::new(String::from("No product version detected")) + e)
            }
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_product_version(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init("product_version".to_string(), index, 0);

    match detect_token(node, http_request, index) {
        Ok(()) => index += node.get_last_child().get_length(),
        Err(e) => {
            node.del_last_child();
            return Err(ParsingError::new(String::from("No token detected")) + e)
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_rws(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init("RWS".to_string(), index, 0);
    let mut count: u8 = 0;

    loop {
        if let Ok(()) = detect_sp(node, http_request, index) {
            count += 1;
            index += node.get_last_child().get_length();
        } else if let Ok(()) = detect_htab(node, http_request, index) {
            count += 1;
            index += node.get_last_child().get_length();
        } else {
            break;
        }
    }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No RWS detected")))
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_comment(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init("comment".to_string(), index, 0);

    if utils::get_request_char(http_request, index as usize) == b'(' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '(' detected")))
    }

    loop {
        if let Ok(()) = detect_ctext(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else if let Ok(()) = detect_quoted_pair(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else if let Ok(()) = detect_comment(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else {
            break;
        }
    }

    if utils::get_request_char(http_request, index as usize) == b')' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No ')' detected")))
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_quoted_pair(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init("quoted_pair".to_string(), index, 0);

    if utils::get_request_char(http_request, index as usize) == b'\\' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '\\' detected")))
    }

    if let Ok(()) = detect_htab(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_sp(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_vchar(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_obs_text(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No quoted pair component detected")))
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_vchar(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    let c: u8 = utils::get_request_char(http_request, index as usize);

    if 0x21 <= c && c <= 0x7E {
        parent.add_child("__vchar".to_string(), index, 1);
    } else {
        return Err(ParsingError::new(String::from("No vchar component detected")))
    }

    Ok(())
}

fn detect_ctext(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init("ctext".to_string(), index, 0);
    let c: u8 = utils::get_request_char(http_request, index as usize);

    if let Ok(()) = detect_htab(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_sp(node, http_request, index) { 
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_obs_text(node, http_request, index) { 
        index += node.get_last_child().get_length();
    } else if 0x21 <= c && c <= 0x27 || 0x2A <= c && c <= 0x5B || 0x5D <= c && c <= 0x7E {
        node.add_child("__range".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No ctext component detected")))
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_obs_text(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    let c: u8 = utils::get_request_char(http_request, index as usize);

    if 0x80 <= c {
        parent.add_child("__range".to_string(), index, 1);
    } else {
        return Err(ParsingError::new(String::from("No obs text component detected")))
    }

    Ok(())
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
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("segment"), index, 0);

    loop {
        if let Ok(()) = detect_pchar(node, http_request, index) {
            index += node.get_last_child().get_length();
        } else {
            break;
        }
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_pchar(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("__pchar"), index, 0);
    let c: u8 = utils::get_request_char(http_request, index as usize);

    if let Ok(()) = detect_unreserved(node, http_request, index) {
            index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_pct_encoded(node, http_request, index) {
            index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_sub_delims(node, http_request, index) {
            index += node.get_last_child().get_length();
    } else if c == b':' || c == b'@' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No pchar component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_unreserved(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("HTTP_version"), index, 0);
    let c: u8 = utils::get_request_char(http_request, index as usize);

    if let Ok(()) = detect_alpha(node, http_request, index) {
        node.add_child("__alpha".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else if let Ok(()) = detect_digit(node, http_request, index) {
        node.add_child("__digit".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else if c == b'-' || c == b'.' || c == b'_' || c == b'~' {
        node.add_child("case_insensitive_string".to_string(), index, 1);
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No pchar component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_pct_encoded(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("pct_encoded"), index, 0);

    if utils::get_request_char(http_request, index as usize) == b'%' {
        index += node.get_last_child().get_length();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '%' detected")));
    }

    if let Ok(()) = detect_hexdig(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else {
        return Err(ParsingError::new(String::from("No hexdig detected")));
    }

    if let Ok(()) = detect_hexdig(node, http_request, index) {
        index += node.get_last_child().get_length();
    } else {
        return Err(ParsingError::new(String::from("No hexdig detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
}

fn detect_hexdig(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    let c: u8 = utils::get_request_char(http_request, index as usize);

    if let Ok(()) = detect_digit(parent, http_request, index) {
        parent.add_child("__hexdig".to_string(), index, 1);
    } else if 0x41 <= c && c <= 0x46 || 0x61 <= c && c <= 0x66 {
        parent.add_child("__hexdig".to_string(), index, 1);
    } else {
        return Err(ParsingError::new(String::from("No hexdig component detected")));
    }

    Ok(())
}

fn detect_sub_delims(parent: &mut Node, http_request: &Box<Vec<u8>>, index: u8) -> Result<(), ParsingError> {
    parent.add_empty_child();
    let node: &mut Node = parent.get_mut_last_child();
    node.init(String::from("pct_encoded"), index, 0);
    let c: u8 = utils::get_request_char(http_request, index as usize);

    if utils::is_in(c, b"!$&'()*+,;=".to_vec()) {
        node.add_child("case_insensitive_string".to_string(), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No subdelims component detected")));
    }

    node.set_length(node.get_sum_length_children());
    Ok(())
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
