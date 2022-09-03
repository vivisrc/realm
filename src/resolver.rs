use colored::Colorize;
use log::trace;

use crate::{
    context::QueryContext,
    message::{Message, Opcode, PacketType, ResponseCode},
    node::Node,
    opt::{OptData, OptHandleAction},
    record::{Record, RecordClass, RecordData, RecordType},
    text::{DomainName, Name},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveType {
    Question,
    Alias,
    Additional,
}

fn find_authorities(node: &Node, qclass: RecordClass) -> &[Record] {
    let soa_records = node.resource_record_set(qclass, RecordType::Soa);
    if !soa_records.is_empty() {
        return soa_records;
    }

    let ns_records = node.resource_record_set(qclass, RecordType::Ns);
    if !ns_records.is_empty() {
        return ns_records;
    }

    &[]
}

fn find_node<'root>(
    name: &DomainName,
    qclass: RecordClass,
    root: &'root Node,
) -> (Option<&'root Node>, &'root [Record]) {
    let mut node = Some(root);
    let mut authorities = find_authorities(root, qclass);

    for label in name.labels().iter().rev() {
        node = node.and_then(|node| node.get(label));
        if let Some(node) = node {
            let node_authorities = find_authorities(node, qclass);
            authorities = match node_authorities.is_empty() {
                true => authorities,
                false => node_authorities,
            };
        }
    }

    (node, authorities)
}

fn resolve_query(query: &Message, response: &mut Message, context: &mut QueryContext) {
    let mut queue = query
        .questions()
        .iter()
        .map(|question| (question.clone(), ResolveType::Question))
        .collect::<Vec<_>>();

    while let Some((question, resolve_type)) = queue.pop() {
        if !context.resolved.insert(question.clone()) {
            continue;
        }

        let (node, authorities) =
            find_node(question.name(), question.qclass(), &context.server.root);

        if authorities.is_empty() && resolve_type == ResolveType::Question {
            response.set_response_code(ResponseCode::QueryRefused);
            return;
        }

        if node.is_none() {
            for authority in authorities {
                response.add_authority(authority.clone());
                queue.append(&mut authority.additionals(&question));

                if resolve_type == ResolveType::Question && authority.rtype() == RecordType::Soa {
                    response.set_response_code(ResponseCode::NonExistentDomain);
                    return;
                }
            }

            continue;
        }
        let node = node.unwrap();

        let mut answers = node.resource_record_set(question.qclass(), RecordType::Cname);
        for answer in answers {
            queue.append(&mut answer.additionals(&question));
        }

        if answers.is_empty() {
            answers = node.resource_record_set(question.qclass(), question.qtype());
        }

        for answer in answers {
            if resolve_type != ResolveType::Additional {
                response.add_answer(answer.clone());
            } else {
                response.add_additional(answer.clone());
            }

            queue.append(&mut answer.additionals(&question))
        }
    }
}

pub async fn resolve_impl(query: &Message, context: &mut QueryContext) -> Message {
    let mut response = Message::new(query.id());
    response
        .set_packet_type(PacketType::Response)
        .set_opcode(query.opcode())
        .set_authoritative_answer(true)
        .set_recursion_desired(query.recursion_desired())
        .set_recursion_available(false)
        .set_response_code(ResponseCode::NoError);

    for question in query.questions() {
        response.add_question(question.clone());
    }

    match query.edns_version() {
        Some(version) => {
            response.set_edns_version(Some(0));
            response.set_udp_payload_size(context.config.server.udp_max_payload_size);

            if version > 0 {
                // BADSIG and BADVERS share the same code
                response.set_response_code(ResponseCode::BadSignature);
                return response;
            }
        }

        None => (),
    }

    for option in query.options() {
        match option.handle(query, &mut response, context) {
            OptHandleAction::Nothing => (),
            OptHandleAction::ReturnEarly => return response,
        };
    }

    if query.opcode() == Opcode::Query {
        resolve_query(query, &mut response, context);
    } else {
        response.set_response_code(ResponseCode::NotImplemented);
    }

    response
}

pub async fn resolve(query: &Message, context: &mut QueryContext) -> Message {
    let response = resolve_impl(query, context).await;

    trace!(
        "Resolved query for {}:\n{}\n{}",
        context.connection.lock().unwrap().addr,
        query.to_string().blue(),
        response.to_string().green(),
    );

    response
}
