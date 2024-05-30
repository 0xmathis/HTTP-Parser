use crate::node::Node;
use crate::parsing_error::ParsingError;
use crate::utils;


pub fn parser(http_request: &Box<Vec<u8>>, length: usize) -> Result<Node, ParsingError> {
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

fn detect_http_message(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    parent.init(String::from("HTTP_message"), index, 0);

    match detect_start_line(parent, http_request, index) {
        Ok(_) => index += parent.get_length_last_child(),
        Err(e) => return Err(ParsingError::new(String::from("No start line detected")) + e)
    }

    while let Ok(_) = detect_header_field(parent, http_request, index) {
        index += parent.get_length_last_child();

        match detect_crlf(parent, http_request, index) {
            Ok(_) => index += parent.get_length_last_child(),
            Err(e) => return Err(ParsingError::new(String::from("No CRLF detected")) + e)
        }
    }

    match detect_crlf(parent, http_request, index) {
        Ok(_) => index += parent.get_length_last_child(),
        Err(e) => return Err(ParsingError::new(String::from("No CRLF detected")) + e)
    }

    let _ = detect_message_body(parent, http_request, index);

    parent.set_length(parent.get_sum_length_children());
    Ok(())
}

fn detect_start_line(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("start_line"), index, 0);

    if let Err(e) = detect_request_line(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No request line detected")) + e);
    } 

    node.update_length();
    Ok(())
}

fn detect_request_line(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("request_line"), index, 0);

    match detect_method(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No method detected")) + e);
        }
    }

    match detect_sp(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No SP detected")) + e);
        }
    }

    match detect_request_target(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No request target detected")) + e);
        }
    }

    match detect_sp(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No SP detected")) + e);
        }
    }

    match detect_http_version(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No HTTP version detected")) + e);
        }
    }

    if let Err(e) = detect_crlf(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No CRLF detected")) + e);
    }

    node.update_length();
    Ok(())
}

fn detect_header_field(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("header_field"), index, 0);

    if detect_connection_header(node, http_request, index) == Ok(()) 
        || detect_content_length_header(node, http_request, index) == Ok(()) 
            || detect_content_type_header(node, http_request, index) == Ok(()) 
            || detect_cookie_header(node, http_request, index) == Ok(()) 
            || detect_transfer_encoding_header(node, http_request, index) == Ok(()) 
            || detect_expect_header(node, http_request, index) == Ok(()) 
            || detect_host_header(node, http_request, index) == Ok(()) 
            || detect_user_agent_header(node, http_request, index) == Ok(()) 
            || detect_accept_language_header(node, http_request, index) == Ok(()) 
            || detect_accept_header(node, http_request, index) == Ok(()) 
            || detect_accept_encoding_header(node, http_request, index) == Ok(()) {
            } else if let Ok(_) = detect_field_name(node, http_request, index) {
                index += node.get_length_last_child();

                if utils::get_request_char(http_request, index) == b':' {
                    node.add_child(String::from("case_insensitive_string"), index, 1);
                    index += node.get_length_last_child();
                } else {
                    parent.del_last_child();
                    return Err(ParsingError::new(String::from("No ':' detected")));
                }

                if let Ok(_) = detect_ows(node, http_request, index) {
                    index += node.get_length_last_child();
                }

                if let Err(e) = detect_field_value(node, http_request, index) {
                    parent.del_last_child();
                    return Err(ParsingError::new(String::from("No field value detected")) + e);
                }

                if node.get_length_last_child() == 0 {
                    node.del_last_child();
                } else {
                    index += node.get_length_last_child();
                }

                let _ = detect_ows(node, http_request, index);
            } else {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No header_field component detected")));
            }

    node.update_length();
    Ok(())
}

fn detect_field_value(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("field_value"), index, 0);

    while detect_field_content(node, http_request, index) == Ok(()) 
        || detect_obs_fold(node, http_request, index) == Ok(()) {
            index += node.get_length_last_child();
        }

    node.update_length();
    Ok(())
}

fn detect_obs_fold(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("obs_fold"), index, 0);
    let mut count: usize = 0;

    match detect_crlf(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No CRLF detected")) + e);
        }
    }

    while detect_sp(node, http_request, index) == Ok(())
        || detect_htab(node, http_request, index) == Ok(()) {
            index += node.get_length_last_child();
            count += 1;
        }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No obs_fold component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_field_content(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("field_content"), index, 0);
    let mut count: usize = 0;

    match detect_field_vchar(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No field_vchar detected")) + e);
        }
    }

    while detect_sp(node, http_request, index) == Ok(())
        || detect_htab(node, http_request, index) == Ok(()) {
            index += node.get_length_last_child();
            count += 1;
        }

    if count >= 1 {
        if let Err(_) = detect_field_vchar(node, http_request, index) {
            while node.get_last_child().get_label() == "__sp" 
                || node.get_last_child().get_label() == "__htab" {
                    node.del_last_child();
                }
        }
    }

    node.update_length();
    Ok(())
}

fn detect_field_vchar(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("field_vchar"), index, 0);

    if detect_vchar(node, http_request, index) != Ok(())
        && detect_obs_text(node, http_request, index) != Ok(()) {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No field_vchar component detected")));
        }

    node.update_length();
    Ok(())
}

fn detect_ows(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("OWS"), index, 0);
    let mut count: usize = 0;

    while detect_sp(node, http_request, index) == Ok(())
        || detect_htab(node, http_request, index) == Ok(()) {
            index += node.get_length_last_child();
            count += 1;
        }

    if count == 0 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No OWS component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_bws(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("BWS"), index, 0);

    if let Err(e) = detect_ows(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No OWS detected")) + e);
    }

    node.update_length();
    Ok(())
}

fn detect_field_name(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("field_name"), index, 0);

    if let Err(e) = detect_token(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No token detected")) + e); 
    }

    node.update_length();
    Ok(())
}

fn detect_accept_encoding_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Accept_Encoding_header"), index, 0);

    if utils::starts_with(b"Accept-Encoding:".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 15);
        index += node.get_length_last_child();
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Accept Encoding string detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    match detect_accept_encoding(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No accept_encoding detected")) + e); 
        }
    }

    let _ = detect_ows(node, http_request, index);

    node.update_length();
    Ok(())
}

fn detect_accept_encoding(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Accept_Encoding"), index, 0);

    if utils::get_request_char(http_request, index) == b',' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else if let Ok(_) = detect_codings(node, http_request, index) {
        index += node.get_length_last_child();

        if let Ok(_) = detect_weight(node, http_request, index) {
            index += node.get_length_last_child();
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No accept_encodings component detected")));
    }

    loop {
        if detect_ows(node, http_request, index) == Ok(()) 
            && utils::get_request_char(http_request, (index + node.get_length_last_child()) as usize) == b',' {
                index += node.get_length_last_child();
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else if utils::get_request_char(http_request, index) == b',' {
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else {
                if node.get_last_child().get_label() == "OWS" {
                    node.del_last_child();
                }

                break;
            }

        if let Ok(_) = detect_ows(node, http_request, index) {
            index += node.get_length_last_child();
        }

        if let Ok(_) = detect_codings(node, http_request, index) {
            index += node.get_length_last_child();

            if let Ok(_) = detect_weight(node, http_request, index) {
                index += node.get_length_last_child();
            }
        }
    }

    node.update_length();
    Ok(())
}

fn detect_weight(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("weight"), index, 0);

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    if utils::get_request_char(http_request, index) == b';' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No ';' detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    if utils::starts_with(b"q=".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 2);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No \"q=\" detected")));
    }

    if let Err(e) = detect_qvalue(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No qvalue detected")) + e);
    }

    node.update_length();
    Ok(())
}

fn detect_qvalue(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("qvalue"), index, 0);
    let mut c: u8 = utils::get_request_char(http_request, index);

    if c == b'0' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
        c = utils::get_request_char(http_request, index);

        if c == b'.' {
            node.add_child(String::from("case_insensitive_string"), index, 1);
            index += node.get_length_last_child();
            let mut count: usize = 0;

            while let Ok(_) = detect_digit(http_request, index) {
                node.add_child(String::from("__digit"), index, 1);
                index += node.get_length_last_child();
                count += 1;
            }

            if count > 3 {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No qvalue component detected")));
            }
        }
    } else if c == b'1' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
        c = utils::get_request_char(http_request, index);

        if c == b'.' {
            node.add_child(String::from("case_insensitive_string"), index, 1);
            index += node.get_length_last_child();
            let mut count: usize = 0;

            while utils::get_request_char(http_request, index) == b'0' {
                node.add_child(String::from("__digit"), index, 1);
                index += node.get_length_last_child();
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

    node.update_length();
    Ok(())
}

fn detect_codings(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("codings"), index, 0);

    if detect_content_codings(node, http_request, index) == Ok(()) {
    } else if utils::starts_with(b"identity".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 8);
    } else if utils::get_request_char(http_request, index) == b'*' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No codings component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_content_codings(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("content_coding"), index, 0);

    if let Err(e) = detect_token(node, http_request, index) {
        return Err(ParsingError::new(String::from("No token detected")) + e);
    }

    node.update_length();
    Ok(())
}

fn detect_accept_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Accept_header"), index, 0);

    if utils::starts_with(b"Accept:".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 6);
        index += node.get_length_last_child();
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Accept string detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    match detect_accept(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No Accept detected")) + e); 
        }
    }

    let _ = detect_ows(node, http_request, index);

    node.update_length();
    Ok(())
}

fn detect_accept(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Accept"), index, 0);

    if utils::get_request_char(http_request, index) == b',' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else if let Ok(_) = detect_media_range(node, http_request, index) {
        index += node.get_length_last_child();

        if let Ok(_) = detect_accept_params(node, http_request, index) {
            index += node.get_length_last_child();
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No accept component detected")));
    }

    loop {
        if detect_ows(node, http_request, index) == Ok(())
            && utils::get_request_char(http_request, index + node.get_length_last_child()) == b',' {
                index += node.get_length_last_child();
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else if utils::get_request_char(http_request, index) == b',' {
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else {
                if node.get_last_child().get_label() == "OWS" {
                    node.del_last_child();
                }

                break;
            }

        if let Ok(_) = detect_ows(node, http_request, index) {
            index += node.get_length_last_child();
        }

        if let Ok(_) = detect_media_range(node, http_request, index) {
            index += node.get_length_last_child();

            if let Ok(_) = detect_accept_params(node, http_request, index) {
                index += node.get_length_last_child();
            }
        }
    }

    node.update_length();
    Ok(())
}

fn detect_accept_params(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("accept_params"), index, 0);

    match detect_weight(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No weight detected")) + e);
        }
    }

    while let Ok(_) =  detect_accept_ext(node, http_request, index) {
        index += node.get_length_last_child();
    }

    node.update_length();
    Ok(())
}

fn detect_accept_ext(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("accept_ext"), index, 0);

    if detect_ows(node, http_request, index) == Ok(()) && utils::get_request_char(http_request, (index + node.get_length_last_child()) as usize) == b';' {
        index += node.get_length_last_child();
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else if utils::get_request_char(http_request, index) == b';' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No accept ext component detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    match detect_token(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No token detected")) + e);
        }
    }

    if utils::get_request_char(http_request, index) == b'='  {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();

        if detect_token(node, http_request, index) != Ok(()) 
            && detect_token(node, http_request, index) != Ok(()) {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No accept ext component detected")));
            }
    }

    node.update_length();
    Ok(())
}

fn detect_media_range(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("media_range"), index, 0);

    if utils::starts_with(b"*/*".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 3);
        index += node.get_length_last_child();
    } else if let Ok(_) = detect_type(node, http_request, index) {
        index += node.get_length_last_child();

        if utils::get_request_char(http_request, index) == b'/' {
            node.add_child(String::from("case_insensitive_string"), index, 1);
            index += node.get_length_last_child();
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No '/' detected")));
        }

        match detect_subtype(node, http_request, index) {
            Ok(_) => index += node.get_length_last_child(),
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
        if detect_ows(node, http_request, index) == Ok(())
            && utils::get_request_char(http_request, (index + node.get_length_last_child()) as usize) == b';' {
                index += node.get_length_last_child();
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else if utils::get_request_char(http_request, index) == b';' {
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else {
                if node.get_last_child().get_label() == "OWS" {
                    node.del_last_child();
                }

                break;
            }

        if let Ok(_) = detect_ows(node, http_request, index) {
            index += node.get_length_last_child();
        }

        match detect_parameter(node, http_request, index) {
            Ok(_) => index += node.get_length_last_child(),
            Err(e) => {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No parameter detected")) + e);
            }
        }
    }

    node.update_length();
    Ok(())
}

fn detect_parameter(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("parameter"), index, 0);

    match detect_token(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No token detected")) + e);
        }
    }

    if utils::get_request_char(http_request, index) == b'=' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '=' detected")));
    }

    if detect_token(node, http_request, index) != Ok(())
        && detect_quoted_string(node, http_request, index) != Ok(()) {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No parameter component detected")));
        }

    node.update_length();
    Ok(())
}

fn detect_type(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("type"), index, 0);

    if let Err(e) = detect_token(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No token detected")) + e);
    }

    node.update_length();
    Ok(())
}

fn detect_subtype(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("subtype"), index, 0);

    if let Err(e) = detect_token(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No token detected")) + e);
    }

    node.update_length();
    Ok(())
}

fn detect_accept_language_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Accept_Language_header"), index, 0);

    if utils::starts_with(b"Accept-Language:".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 15);
        index += node.get_length_last_child();
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Accept Language string detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    match detect_accept_language(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No accept language detected")) + e); 
        }
    }

    let _ = detect_ows(node, http_request, index);

    node.update_length();
    Ok(())
}

fn detect_accept_language(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Accept_Language"), index, 0);

    while utils::get_request_char(http_request, index) == b',' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();

        if let Ok(_) = detect_ows(node, http_request, index) {
            index += node.get_length_last_child();
        }
    }

    match detect_language_range(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No language_range detected")) + e); 
        }
    }

    if let Ok(_) = detect_weight(node, http_request, index) {
        index += node.get_length_last_child();
    }

    loop {
        if detect_ows(node, http_request, index) == Ok(())
            && utils::get_request_char(http_request, (index + node.get_length_last_child()) as usize) == b',' {
                index += node.get_length_last_child();
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else if utils::get_request_char(http_request, index) == b',' {
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else {
                if node.get_last_child().get_label() == "OWS" {
                    node.del_last_child();
                }

                break;
            }

        if let Ok(_) = detect_ows(node, http_request, index) {
            index += node.get_length_last_child();
        }

        if let Ok(_) = detect_language_range(node, http_request, index) {
            index += node.get_length_last_child();

            if let Ok(_) = detect_weight(node, http_request, index) {
                index += node.get_length_last_child();
            }
        }
    }

    node.update_length();
    Ok(())
}

fn detect_language_range(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("language_range"), index, 0);

    if utils::get_request_char(http_request, index) == b'*' {
        node.add_child(String::from("case_insensitive_string"), index, 10);
    } else if let Ok(_) = detect_alpha(http_request, index) {
        node.add_child(String::from("__alpha"), index, 1);
        index += node.get_length_last_child();
        let mut count: usize = 1;

        while let Ok(_) = detect_alpha(http_request, index) {
            node.add_child(String::from("__alpha"), index, 1);
            index += node.get_length_last_child();
            count += 1;
        }

        if count > 8 {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No language_range component detected")));
        }

        while utils::get_request_char(http_request, index) == b'-' {
            node.add_child(String::from("case_insensitive_string"), index, 1);
            index += node.get_length_last_child();
            let mut count: usize = 0;

            while let Ok(_) = detect_alphanum(node, http_request, index) {
                index += node.get_length_last_child();
                count += 1;
            }

            if count < 1 || count > 8 {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No language_range component detected")));
            }
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No language_range component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_alphanum(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("alphanum"), index, 0);

    if let Ok(_) = detect_alpha(http_request, index) {
        node.add_child(String::from("__alpha"), index, 1);
    } else if let Ok(_) = detect_digit(http_request, index) {
        node.add_child(String::from("__digit"), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No alphanum component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_user_agent_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("User_Agent_header"), index, 0);

    if utils::starts_with(b"User-Agent:".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 10);
        index += node.get_length_last_child();
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No User Agent string detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    match detect_user_agent(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No User Agent detected")) + e); 
        }
    }

    let _ = detect_ows(node, http_request, index);

    node.update_length();
    Ok(())
}

fn detect_host_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Host_header"), index, 0);

    if utils::starts_with(b"Host:".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 4);
        index += node.get_length_last_child();
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Host string detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    if let Ok(_) = detect_host(node, http_request, index) {
        if node.get_length_last_child() == 0 {
            node.del_last_child();
        } else {
            index += node.get_length_last_child();
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Host detected"))); 
    }

    let _ = detect_ows(node, http_request, index);

    node.update_length();
    Ok(())
}

fn detect_host(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Host"), index, 0);

    match detect_uri_host(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No uri_host detected")) + e); 
        }
    }

    if utils::get_request_char(http_request, index) == b':' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();

        if let Err(e) = detect_port(node, http_request, index) {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No port detected")) + e); 
        }
    }

    node.update_length();
    Ok(())
}

fn detect_uri_host(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("uri_host"), index, 0);

    if let Err(e) = detect_host_(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No host detected")) + e); 
    }

    node.update_length();

    if node.get_length() == 0 {
        parent.del_last_child();
    }

    Ok(())
}

fn detect_host_(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("host"), index, 0);

    if detect_ip_literal(node, http_request, index) != Ok(()) 
        && detect_ipv4address(node, http_request, index) != Ok(()) 
            && detect_reg_name(node, http_request, index) != Ok(()) {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No host component detected"))); 
            }

    node.update_length();
    Ok(())
}

fn detect_reg_name(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("reg_name"), index, 0);

    while detect_unreserved(node, http_request, index) == Ok(())
        || detect_pct_encoded(node, http_request, index) == Ok(())
            || detect_sub_delims(node, http_request, index) == Ok(()) {
                index += node.get_length_last_child();
            }

    node.update_length();
    Ok(())
}

fn detect_ipv4address(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("IPv4address"), index, 0);

    for _ in 0..3 {
        match detect_dec_octet(node, http_request, index) {
            Ok(_) => index += node.get_length_last_child(),
            Err(e) => {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No dec_octet detected")) + e);
            }
        }

        if utils::get_request_char(http_request, index) == b'.' {
            node.add_child(String::from("case_insensitive_string"), index, 1);
            index += node.get_length_last_child();
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No reg name component detected")));
        }
    }

    if let Err(e) = detect_dec_octet(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No reg name component detected")) + e);
    }

    node.update_length();
    Ok(())
}

fn detect_dec_octet(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("dec_octet"), index, 0);

    let c0: u8 = utils::get_request_char(http_request, index);
    let c1: u8 = utils::get_request_char(http_request, index + 1);
    let c2: u8 = utils::get_request_char(http_request, index + 2);

    if c0 == b'2' && c1 == b'5' && b'0' <= c2 && c2 <= b'5' {
        node.add_child(String::from("case_insensitive_string"), index, 2);
        node.add_child(String::from("__digit"), index + 2, 1);
    } else if c0 == b'2' && b'0' <= c1 && c1 <= b'4' && detect_digit(http_request, index + 2) == Ok(()) {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        node.add_child(String::from("__range"), index + 1, 1);
        node.add_child(String::from("__digit"), index + 2, 1);
    } else if c0 == b'1' && detect_digit(http_request, index + 1) == Ok(()) && detect_digit(http_request, index + 2) == Ok(()) {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        node.add_child(String::from("__digit"), index + 1, 1);
        node.add_child(String::from("__digit"), index + 2, 1);
    } else if  b'1' <= c0 && c0 <= b'9' && detect_digit(http_request, index + 1) == Ok(()) {
        node.add_child(String::from("__range"), index, 1);
        node.add_child(String::from("__digit"), index + 1, 1);
    } else if detect_digit(http_request, index) == Ok(()) {
        node.add_child(String::from("__digit"), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No dec_octet detected"))); 
    }

    node.update_length();
    Ok(())
}

fn detect_ip_literal(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("IP_literal"), index, 0);

    if utils::get_request_char(http_request, index) == b'[' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '[' detected"))); 
    }

    if detect_ipvfuture(node, http_request, index) == Ok(()) 
        || detect_ipv6address(node, http_request, index) == Ok(()){
            index += node.get_length_last_child();
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No ip_literal component detected"))); 
        }

    if utils::get_request_char(http_request, index) == b']' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No ']' detected"))); 
    }

    node.update_length();
    Ok(())
}

fn detect_ipvfuture(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("IPvFuture"), index, 0);
    let mut count: usize;
    let c: u8 = utils::get_request_char(http_request, index);

    if c == b'v' || c == b'V' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '[' detected"))); 
    }

    count = 0;

    while let Ok(_) = detect_hexdig(node, http_request, index) {
        index += node.get_length_last_child();
        count += 1;
    }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No IPvFuture component detected"))); 
    }

    if utils::get_request_char(http_request, index) == b'.' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '.' detected"))); 
    }

    count = 0;

    loop {
        if detect_unreserved(node, http_request, index) == Ok(())
            || detect_sub_delims(node, http_request, index) == Ok(()) {
            } else if utils::get_request_char(http_request, index) == b':' {
                node.add_child(String::from("case_insensitive_string"), index, 1);
            } else {
                break;
            }

        index += node.get_length_last_child();
        count += 1;
    }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No IPvFuture component detected"))); 
    }

    node.update_length();
    Ok(())
}

fn detect_ipv6address(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("IPv6address"), index, 0);
    let mut count: usize = 0;

    while count != 6 {
        match detect_h16(node, http_request, index) {
            Ok(_) => index += node.get_length_last_child(),
            Err(_) => break
        }

        count += 1;

        if utils::starts_with(b"::".to_vec(), http_request, index) {
            break;
        }

        if utils::get_request_char(http_request, index) == b':' {
            node.add_child(String::from("case_insensitive_string"), index, 1);
            index += node.get_length_last_child();
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No IPv6address component detected"))); 
        }
    }

    if count == 6 {
        if let Ok(_) = detect_ls32(node, http_request, index) {
        } else if let Ok(_) = detect_h16(node, http_request, index) {
            index += node.get_length_last_child();

            if utils::starts_with(b"::".to_vec(), http_request, index) {
                node.add_child(String::from("case_insensitive_string"), index, 2);
            } else {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No IPv6address component detected"))); 
            }
        } else if utils::starts_with(b"::".to_vec(), http_request, index) {
            node.add_child(String::from("case_insensitive_string"), index, 2);
            index += node.get_length_last_child();

            if let Ok(_) = detect_h16(node, http_request, index) {
            }
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No IPv6address component detected"))); 
        }
    } else if utils::starts_with(b"::".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 2);
        index += node.get_length_last_child();

        loop {
            if detect_ls32(node, http_request, index) == Ok(())
                && utils::get_request_char(http_request, index + node.get_length_last_child()) == b']' {
                    if count > 5 {
                        parent.del_last_child();
                        return Err(ParsingError::new(String::from("No IPv6address component detected"))); 
                    }

                    break
                } else if node.get_last_child().get_label() == "ls32" {
                    node.del_last_child();
                }

            if let Ok(_) = detect_h16(node, http_request, index) {
                index += node.get_length_last_child();
                count += 1;

                if utils::get_request_char(http_request, index) == b']' {
                    break;
                }
            } else {
                break;
            }

            if utils::get_request_char(http_request, index) == b':' {
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No IPv6address component detected"))); 
            }
        }
    }

    node.update_length();
    Ok(())
}

fn detect_h16(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("h16"), index, 0);
    let mut count: usize = 0;

    while let Ok(_) = detect_hexdig(node, http_request, index) {
        index += node.get_length_last_child();
        count += 1;
    }

    if count < 1 || 4 < count {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No h16 component detected"))); 
    }

    node.update_length();
    Ok(())
}

fn detect_ls32(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("ls32"), index, 0);

    if  let Ok(_) = detect_ipv4address(node, http_request, index) {
    } else if let Ok(_) = detect_h16(node, http_request, index) {
        index += node.get_length_last_child();

        if utils::get_request_char(http_request, index) == b':' {
            node.add_child(String::from("case_insensitive_string"), index, 1);
            index += node.get_length_last_child();

            if let Err(e) = detect_h16(node, http_request, index) {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No h16 detected")) + e); 
            }
        } else {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No ls32 component detected"))); 
        }
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No ls32 component detected"))); 
    }

    node.update_length();
    Ok(())
}

fn detect_port(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("port"), index, 0);
    let mut count: usize = 0;

    while let Ok(_) = detect_digit(http_request, index) {
        node.add_child(String::from("__digit"), index, 1);
        index += node.get_length_last_child();
        count += 1;
    }

    if count == 0 {
        parent.del_last_child();
        return Ok(());
    }

    node.update_length();
    Ok(())
}

fn detect_expect_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Expect_header"), index, 0);

    if utils::starts_with(b"Expect:".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 6);
        index += node.get_length_last_child();
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Expect string detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    match detect_expect(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No expect detected")) + e); 
        }
    }

    let _ = detect_ows(node, http_request, index);

    node.update_length();
    Ok(())
}

fn detect_expect(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Expect"), index, 0);

    if utils::starts_with(b"100-continue".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 12);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No \"100-continue\" detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_transfer_encoding_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Transfer_Encoding_header"), index, 0);

    if utils::starts_with(b"Transfer-Encoding:".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 17);
        index += node.get_length_last_child();
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Transfer_Encoding string detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    match detect_transfer_encoding(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No transfer_encoding detected")) + e); 
        }
    }

    let _ = detect_ows(node, http_request, index);

    node.update_length();
    Ok(())
}

fn detect_transfer_encoding(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Transfer_Encoding"), index, 0);

    while utils::get_request_char(http_request, index) == b',' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();

        if let Ok(_) = detect_ows(node, http_request, index) {
            index += node.get_length_last_child();
        }
    }

    match detect_transfer_coding(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No transfer_coding detected")) + e); 
        }
    }

    loop {
        if detect_ows(node, http_request, index) == Ok(())
            && utils::get_request_char(http_request, (index + node.get_length_last_child()) as usize) == b',' {
                index += node.get_length_last_child();
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else if utils::get_request_char(http_request, index) == b',' {
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else {
                if node.get_last_child().get_label() == "OWS" {
                    node.del_last_child();
                }

                break;
            }

        if let Ok(_) = detect_ows(node, http_request, index) {
            index += node.get_length_last_child();
        }

        if let Ok(_) = detect_transfer_coding(node, http_request, index) {
            index += node.get_length_last_child();
        }
    }

    node.update_length();
    Ok(())
}

fn detect_transfer_coding(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("transfer_coding"), index, 0);

    if utils::starts_with(b"chunked".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 7);
    } else if utils::starts_with(b"compress".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 8);
    } else if utils::starts_with(b"deflate".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 7);
    } else if utils::starts_with(b"gzip".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 4);
    } else if let Ok(_) = detect_transfer_extension(node, http_request, index) {
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No transfer_coding component detected"))); 
    }

    node.update_length();
    Ok(())
}

fn detect_transfer_extension(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("transfer_extension"), index, 0);

    match detect_token(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No token detected")) + e); 
        }
    }

    loop {
        if detect_ows(node, http_request, index) == Ok(())
            && utils::get_request_char(http_request, (index + node.get_length_last_child()) as usize) == b';' {
                index += node.get_length_last_child();
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else if utils::get_request_char(http_request, index) == b';' {
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else {
                if node.get_last_child().get_label() == "OWS" {
                    node.del_last_child();
                }

                break;
            }

        if let Ok(_) = detect_ows(node, http_request, index) {
            index += node.get_length_last_child();
        }

        if let Ok(_) = detect_transfer_parameter(node, http_request, index) {
            index += node.get_length_last_child();
        }
    }

    node.update_length();
    Ok(())
}

fn detect_transfer_parameter(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("transfer_parameter"), index, 0);

    match detect_token(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No token detected")) + e); 
        }
    }

    if let Ok(_) = detect_bws(node, http_request, index) {
        index += node.get_length_last_child();
    }

    if utils::get_request_char(http_request, index) == b'=' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    }

    if let Ok(_) = detect_bws(node, http_request, index) {
        index += node.get_length_last_child();
    }

    if detect_token(node, http_request, index) != Ok(())
        && detect_quoted_string(node, http_request, index) != Ok(()) {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No transfer_parameter component detected"))); 
        }

    node.update_length();
    Ok(())
}

fn detect_quoted_string(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("quoted_string"), index, 0);

    match detect_dquote(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No dquote detected")) + e); 
        }
    }

    while detect_qdtext(node, http_request, index) == Ok(())
        || detect_quoted_pair(node, http_request, index) == Ok(()) {
            index += node.get_length_last_child();
        }

    if let Err(e) = detect_dquote(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No dquote detected")) + e); 
    }

    node.update_length();
    Ok(())
}

fn detect_qdtext(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("qdtext"), index, 0);
    let c: u8 = utils::get_request_char(http_request, index);

    if detect_sp(node, http_request, index) == Ok(())
        || detect_htab(node, http_request, index) == Ok(())
            || detect_obs_text(node, http_request, index) == Ok(()) {
            } else if c == b'!' {
                node.add_child(String::from("case_insensitive_string"), index, 1);
            } else if 0x23 <= c && c <= 0x5B || 0x5D <= c && c <= 0x7E {
                node.add_child(String::from("__range"), index, 1);
            } else {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No qdtext component detected")));
            }

    node.update_length();
    Ok(())
}

fn detect_cookie_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Cookie_header"), index, 0);

    if utils::starts_with(b"Cookie:".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 7);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Cookie string detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    match detect_cookie_string(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No cookie string detected")) + e); 
        }
    }

    let _ = detect_ows(node, http_request, index);

    node.update_length();
    Ok(())
}

fn detect_cookie_string(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("cookie_string"), index, 0);

    match detect_cookie_pair(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No cookie pair detected")) + e); 
        }
    }

    while utils::get_request_char(http_request, index) == b';' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();

        match detect_sp(node, http_request, index) {
            Ok(_) => index += node.get_length_last_child(),
            Err(e) => { 
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No sp detected")) + e); 
            }
        }

        match detect_cookie_pair(node, http_request, index) {
            Ok(_) => index += node.get_length_last_child(),
            Err(e) => { 
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No cookie_pair detected")) + e); 
            }
        }
    }

    node.update_length();
    Ok(())
}

fn detect_cookie_pair(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("cookie_pair"), index, 0);

    match detect_cookie_name(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No cookie_name detected")) + e); 
        }
    }

    if utils::get_request_char(http_request, index) == b'=' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '=' detected"))); 
    }

    if let Err(e) = detect_cookie_value(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No cookie_value detected")) + e); 
    }

    node.update_length();
    Ok(())
}

fn detect_cookie_value(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("cookie_value"), index, 0);

    if let Ok(_) = detect_dquote(node, http_request, index) {
        index += node.get_length_last_child();

        while let Ok(_) = detect_cookie_octet(node, http_request, index) {
            index += node.get_length_last_child();
        }

        if let Err(e) = detect_dquote(node, http_request, index) {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No cookie value component detected")) + e); 
        }
    } else {
        let mut count: usize = 0;

        while let Ok(_) = detect_cookie_octet(node, http_request, index) {
            index += node.get_length_last_child();
            count += 1;
        }

        if count == 0 {
            parent.del_last_child();
            return Ok(());
        }
    }

    node.update_length();
    Ok(())
}

fn detect_cookie_octet(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("cookie_octet"), index, 0);

    match utils::get_request_char(http_request, index) {
        b'!' => node.add_child(String::from("__num"), index, 1),
        0x23..=0x2B
            | 0x2D..=0x3A 
            | 0x3C..=0x5B
            | 0x5D..=0x7E => node.add_child(String::from("__range"), index, 1),
        _ => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No cookie_value component detected"))); 
        }
    }

    node.update_length();
    Ok(())
}

fn detect_dquote(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    if utils::get_request_char(http_request, index) == b'"' {
        parent.add_child(String::from("__dquote"), index, 1);
    } else {
        return Err(ParsingError::new(String::from("No '\"' detected")))
    }

    Ok(())
}

fn detect_cookie_name(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("cookie_name"), index, 0);

    if let Err(e) = detect_token(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No token detected")) + e); 
    }

    node.update_length();
    Ok(())
}

fn detect_content_type_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Content_Type_header"), index, 0);

    if utils::starts_with(b"Content-Type:".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 12);
        index += node.get_length_last_child();
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Content Length string detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    match detect_content_type(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No content type detected")) + e); 
        }
    }

    let _ = detect_ows(node, http_request, index);

    node.update_length();
    Ok(())
}

fn detect_content_type(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Content_Type"), index, 0);

    if let Err(e) = detect_media_type(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No media type detected")) + e); 
    }

    node.update_length();
    Ok(())
}

fn detect_media_type(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("media_type"), index, 0);

    match detect_type(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No type detected")) + e); 
        }
    }

    if utils::get_request_char(http_request, index) == b'/' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No type detected"))); 
    }

    match detect_subtype(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No subtype detected")) + e); 
        }
    }

    loop {
        if detect_ows(node, http_request, index) == Ok(())
            && utils::get_request_char(http_request, (index + node.get_length_last_child()) as usize) == b';' {
                index += node.get_length_last_child();
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else if utils::get_request_char(http_request, index) == b';' {
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else {
                if node.get_last_child().get_label() == "OWS" {
                    node.del_last_child();
                }

                break;
            }

        if let Ok(_) = detect_ows(node, http_request, index) {
            index += node.get_length_last_child();
        }

        if let Ok(_) = detect_parameter(node, http_request, index) {
            index += node.get_length_last_child();
        }
    }

    node.update_length();
    Ok(())
}

fn detect_content_length_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Content_Length_header"), index, 0);

    if utils::starts_with(b"Content-Length:".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 14);
        index += node.get_length_last_child();
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Content Length string detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    match detect_content_length(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No content length detected")) + e); 
        }
    }

    let _ = detect_ows(node, http_request, index);

    node.update_length();
    Ok(())
}

fn detect_content_length(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Content_Length"), index, 0);
    let mut count: usize = 0;

    while let Ok(_) = detect_digit(http_request, index) {
        node.add_child(String::from("__digit"), index, 1);
        index += node.get_length_last_child();
        count += 1;
    }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No content_length component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_connection_header(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Connection_header"), index, 0);

    if utils::starts_with(b"Connection:".to_vec(), http_request, index) {
        node.add_child(String::from("case_insensitive_string"), index, 10);
        index += node.get_length_last_child();
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No Connection string detected")));
    }

    if let Ok(_) = detect_ows(node, http_request, index) {
        index += node.get_length_last_child();
    }

    match detect_connection(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => { 
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No Connection detected")) + e); 
        }
    }

    let _ = detect_ows(node, http_request, index);

    node.update_length();
    Ok(())
}

fn detect_connection(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("Connection"), index, 0);

    while utils::get_request_char(http_request, index) == b',' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();

        if let Ok(_) = detect_ows(node, http_request, index) {
            index += node.get_length_last_child();
        }
    }

    match detect_connection_option(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No connection option detected")) + e);
        }
    }

    loop {
        if detect_ows(node, http_request, index) == Ok(())
            && utils::get_request_char(http_request, (index + node.get_length_last_child()) as usize) == b',' {
                index += node.get_length_last_child();
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else if utils::get_request_char(http_request, index) == b',' {
                node.add_child(String::from("case_insensitive_string"), index, 1);
                index += node.get_length_last_child();
            } else {
                if node.get_last_child().get_label() == "OWS" {
                    node.del_last_child();
                }

                break;
            }

        if let Ok(_) = detect_ows(node, http_request, index) {
            index += node.get_length_last_child();
        }

        if let Ok(_) = detect_connection_option(node, http_request, index) {
            index += node.get_length_last_child();
        }
    }

    node.update_length();
    Ok(())
}

fn detect_connection_option(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("connection_option"), index, 0);

    if let Err(e) = detect_token(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No token detected")) + e);
    }

    node.update_length();
    Ok(())
}

fn detect_user_agent(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("User_Agent"), index, 0);

    match detect_product(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No product detected")) + e);
        }
    }

    while let Ok(_) = detect_rws(node, http_request, index) {
        index += node.get_length_last_child();

        if detect_product(node, http_request, index) == Ok(())
            || detect_comment(node, http_request, index) == Ok(()) {
                index += node.get_length_last_child();
            } else {
                node.del_last_child();
                break;
            }
    }

    node.update_length();
    Ok(())
}

fn detect_product(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("product"), index, 0);

    match detect_token(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No token detected")) + e)
        }
    }

    if utils::get_request_char(http_request, index) == b'/' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();

        if let Err(e) = detect_product_version(node, http_request, index) {
            node.del_last_child();
            return Err(ParsingError::new(String::from("No product_version detected")) + e)
        }
    }

    node.update_length();
    Ok(())
}

fn detect_product_version(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("product_version"), index, 0);

    if let Err(e) = detect_token(node, http_request, index) {
        node.del_last_child();
        return Err(ParsingError::new(String::from("No token detected")) + e)
    }

    node.update_length();
    Ok(())
}

fn detect_rws(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("RWS"), index, 0);
    let mut count: usize = 0;

    while detect_sp(node, http_request, index) == Ok(())
        || detect_htab(node, http_request, index) == Ok(()) {
            index += node.get_length_last_child();
            count += 1;
        }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No RWS detected")))
    }

    node.update_length();
    Ok(())
}

fn detect_comment(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("comment"), index, 0);

    if utils::get_request_char(http_request, index) == b'(' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '(' detected")))
    }

    while detect_ctext(node, http_request, index) == Ok(())
        || detect_quoted_pair(node, http_request, index) == Ok(())
            || detect_comment(node, http_request, index) == Ok(()) {
                index += node.get_length_last_child();
            }

    if utils::get_request_char(http_request, index) == b')' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No ')' detected")))
    }

    node.update_length();
    Ok(())
}

fn detect_quoted_pair(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("quoted_pair"), index, 0);

    if utils::get_request_char(http_request, index) == b'\\' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '\\' detected")))
    }

    if detect_htab(node, http_request, index) != Ok(())
        && detect_sp(node, http_request, index) != Ok(())
            && detect_vchar(node, http_request, index) != Ok(())
            && detect_obs_text(node, http_request, index) != Ok(()) {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No quoted pair component detected")))
            }

    node.update_length();
    Ok(())
}

fn detect_vchar(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    match utils::get_request_char(http_request, index) {
        0x21..=0x7E => parent.add_child(String::from("__vchar"), index, 1),
        _ => return Err(ParsingError::new(String::from("No vchar component detected"))),
    }

    Ok(())
}

fn detect_ctext(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("ctext"), index, 0);
    let c: u8 = utils::get_request_char(http_request, index);

    if detect_htab(node, http_request, index) == Ok(())
        || detect_sp(node, http_request, index) == Ok(())
            || detect_obs_text(node, http_request, index) == Ok(()) { 
            } else if 0x21 <= c && c <= 0x27 || 0x2A <= c && c <= 0x5B || 0x5D <= c && c <= 0x7E {
                node.add_child(String::from("__range"), index, 1);
            } else {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No ctext component detected")))
            }

    node.update_length();
    Ok(())
}

fn detect_obs_text(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("obs_text"), index, 0);

    if 0x80 <= utils::get_request_char(http_request, index) {
        node.add_child(String::from("__range"), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No obs_text component detected")))
    }

    node.update_length();
    Ok(())
}

fn detect_crlf(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    if utils::starts_with(b"\r\n".to_vec(), http_request, index) {
        parent.add_child(String::from("__crlf"), index, 2);
    } else {
        return Err(ParsingError::new(String::from("No \\r\\n detected")))
    }

    Ok(())
}

fn detect_message_body(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("message_body"), index, 0);
    let mut count: usize = 0;

    while let Ok(_) = detect_octet(node, http_request, index) {
        index += node.get_length_last_child();
        count += 1;
    }

    if count == 0 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No message_body component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_octet(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    if 0x01 <= utils::get_request_char(http_request, index) {
        parent.add_child(String::from("__octet"), index, 1);
    } else {
        return Err(ParsingError::new(String::from("No octet component detected")));
    }

    Ok(())
}

fn detect_method(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("method"), index, 0);

    if let Err(e) = detect_token(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No token detected")) + e);
    }

    node.update_length();
    Ok(())
}

fn detect_token(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("token"), index, 0);
    let mut count: usize = 0;

    while let Ok(_) = detect_tchar(node, http_request, index) {
        index += node.get_length_last_child();
        count += 1;
    }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No tchar detected")));
    }

    node.update_length();
    Ok(())
}


fn detect_tchar(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("tchar"), index, 0);

    if utils::is_in(utils::get_request_char(http_request, index), b"!#$%&'*+-.^_`|~".to_vec()) {
        node.add_child(String::from("case_insensitive_string"), index, 1);
    } else if let Ok(_) = detect_digit(http_request, index) {
        node.add_child(String::from("__digit"), index, 1);
    } else if let Ok(_) = detect_alpha(http_request, index) {
        node.add_child(String::from("__alpha"), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No tchar component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_alpha(http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    match utils::get_request_char(http_request, index) {
        0x41..=0x5A | 0x61..=0x7A => Ok(()),
        _ => Err(ParsingError::new(String::from("No alpha component detected"))),
    }
}

fn detect_digit(http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    match utils::get_request_char(http_request, index) {
        0x30..=0x39 => Ok(()),
        _ => Err(ParsingError::new(String::from("No digit component detected"))),
    }
}

fn detect_request_target(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("request_target"), index, 0);

    if let Err(e) = detect_origin_form(node, http_request, index) {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No origin_form detected")) + e);
    }

    node.update_length();
    Ok(())
}

fn detect_origin_form(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("origin_form"), index, 0);

    match detect_absolute_path(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No absolute_path detected")) + e);
        }
    }

    if utils::get_request_char(http_request, index) == b'?' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();


        if let Err(e) = detect_query(node, http_request, index) {
            parent.del_last_child();
            return Err(ParsingError::new(String::from("No query detected")) + e);
        }
    }

    node.update_length();
    Ok(())
}

fn detect_query(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("query"), index, 0);
    let mut count: usize = 0;

    loop {
        let c: u8 = utils::get_request_char(http_request, index);

        if let Ok(_) = detect_pchar(node, http_request, index) {
        } else if c == b'/' || c == b'?' {
            node.add_child(String::from("case_insensitive_string"), index, 1);
        } else {
            break;
        }

        index += node.get_length_last_child();
        count += 1;
    }

    if count < 1 {
        parent.del_last_child();
        return Ok(());
    }

    node.update_length();
    Ok(())
}

fn detect_absolute_path(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("absolute_path"), index, 0);
    let mut count: usize = 0;

    while utils::get_request_char(http_request, index) == b'/' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();

        if utils::get_request_char(http_request, index) != b'?' {
            if let Ok(_) = detect_segment(node, http_request, index) {
                index += node.get_length_last_child();
            }
        }

        count += 1;
    }

    if count < 1 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No absolute_path detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_segment(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("segment"), index, 0);
    let mut count: usize = 0;

    while let Ok(_) = detect_pchar(node, http_request, index) {
        index += node.get_length_last_child();
        count += 1;
    }

    if count == 0 {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No segment component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_pchar(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("pchar"), index, 0);
    let c: u8 = utils::get_request_char(http_request, index);

    if detect_unreserved(node, http_request, index) == Ok(())
        || detect_pct_encoded(node, http_request, index) == Ok(())
            || detect_sub_delims(node, http_request, index) == Ok(()) {
            } else if utils::is_in(c, b":@".to_vec()) {
                node.add_child(String::from("case_insensitive_string"), index, 1);
            } else {
                parent.del_last_child();
                return Err(ParsingError::new(String::from("No pchar component detected")));
            }

    node.update_length();
    Ok(())
}

fn detect_unreserved(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("unreserved"), index, 0);
    let c: u8 = utils::get_request_char(http_request, index);

    if let Ok(_) = detect_alpha(http_request, index) {
        node.add_child(String::from("__alpha"), index, 1);
    } else if let Ok(_) = detect_digit(http_request, index) {
        node.add_child(String::from("__digit"), index, 1);
    } else if utils::is_in(c, b"-._~".to_vec()) {
        node.add_child(String::from("case_insensitive_string"), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No pchar component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_pct_encoded(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("pct_encoded"), index, 0);

    if utils::get_request_char(http_request, index) == b'%' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '%' detected")));
    }

    if let Ok(_) = detect_hexdig(node, http_request, index) {
        index += node.get_length_last_child();
    } else {
        return Err(ParsingError::new(String::from("No hexdig detected")));
    }

    if let Err(e) = detect_hexdig(node, http_request, index) {
        return Err(ParsingError::new(String::from("No hexdig detected")) + e);
    }

    node.update_length();
    Ok(())
}

fn detect_hexdig(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let c: u8 = utils::get_request_char(http_request, index);

    if let Ok(_) = detect_digit(http_request, index) {
        parent.add_child(String::from("__hexdig"), index, 1);
    } else if 0x41 <= c && c <= 0x46 || 0x61 <= c && c <= 0x66 {
        parent.add_child(String::from("__hexdig"), index, 1);
    } else {
        return Err(ParsingError::new(String::from("No hexdig component detected")));
    }

    Ok(())
}

fn detect_sub_delims(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("sub_delims"), index, 0);
    let c: u8 = utils::get_request_char(http_request, index);

    if utils::is_in(c, b"!$&'()*+,;=".to_vec()) {
        node.add_child(String::from("case_insensitive_string"), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No sub_delims component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_http_version(parent: &mut Node, http_request: &Box<Vec<u8>>, mut index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("HTTP_version"), index, 0);

    match detect_http_name(node, http_request, index) {
        Ok(_) => index += node.get_length_last_child(),
        Err(e) => return Err(ParsingError::new(String::from("No HTTP name detected")) + e),
    }

    if utils::get_request_char(http_request, index) == b'/' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No '/' detected")));
    }

    if let Ok(_) = detect_digit(http_request, index) {
        node.add_child(String::from("__digit"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No digit detected")));
    }

    if utils::get_request_char(http_request, index) == b'.' {
        node.add_child(String::from("case_insensitive_string"), index, 1);
        index += node.get_length_last_child();
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No . detected")));
    }

    if let Ok(_) = detect_digit(http_request, index) {
        node.add_child(String::from("__digit"), index, 1);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No digit detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_http_name(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    let node: &mut Node = parent.add_get_mut_child(String::from("HTTP_name"), index, 0);

    if utils::starts_with(b"HTTP".to_vec(), http_request, index) {
        node.add_child(String::from("__num"), index, 4);
    } else {
        parent.del_last_child();
        return Err(ParsingError::new(String::from("No HTTP name component detected")));
    }

    node.update_length();
    Ok(())
}

fn detect_sp(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    if utils::get_request_char(http_request, index) == b' ' {
        parent.add_child(String::from("__sp"), index, 1);
    } else {
        return Err(ParsingError::new(String::from("No space detected")))
    }

    Ok(())
}

fn detect_htab(parent: &mut Node, http_request: &Box<Vec<u8>>, index: usize) -> Result<(), ParsingError> {
    if utils::get_request_char(http_request, index) == b'\t' {
        parent.add_child(String::from("__htab"), index, 1);
    } else {
        return Err(ParsingError::new(String::from("No htab detected")))
    }

    Ok(())
}
