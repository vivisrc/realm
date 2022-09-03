use std::collections::HashMap;

use crate::{
    record::{Record, RecordClass, RecordData, RecordType},
    text::Label,
};

/// A node in the domain name space
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Node {
    children: HashMap<Label, Node>,
    records: HashMap<(RecordClass, RecordType), Vec<Record>>,
}

impl Node {
    /// Creates an empty node
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
            records: HashMap::new(),
        }
    }

    /// Gets a child node from the current node
    pub fn get(&self, label: &Label) -> Option<&Node> {
        self.children.get(label)
    }

    /// Gets a child node from the current node and inserts the node if it is not present
    pub fn insert(&mut self, label: Label) -> &mut Node {
        self.children.entry(label).or_insert_with(Default::default)
    }

    /// Removes a child node from the current node and returns it if it existed
    pub fn remove(&mut self, label: &Label) -> Option<Node> {
        self.children.remove(label)
    }

    /// Retrieve the records for this node for a given record class and record type
    pub fn resource_record_set(&self, rclass: RecordClass, rtype: RecordType) -> &[Record] {
        self.records()
            .get(&(rclass, rtype))
            .map(|records| &records[..])
            .unwrap_or_default()
    }

    /// Adds a record to this node
    pub fn add_record(&mut self, record: Record) {
        self.records
            .entry((record.rclass(), record.rtype()))
            .or_default()
            .push(record)
    }

    /// The child nodes of this node
    pub fn children(&self) -> &HashMap<Label, Node> {
        &self.children
    }

    /// A mutable borrow to the child nodes of this node
    pub fn children_mut(&mut self) -> &mut HashMap<Label, Node> {
        &mut self.children
    }

    /// The records associated with this node
    pub fn records(&self) -> &HashMap<(RecordClass, RecordType), Vec<Record>> {
        &self.records
    }

    /// A mutable borrow to the records associated with this node
    pub fn records_mut(&mut self) -> &mut HashMap<(RecordClass, RecordType), Vec<Record>> {
        &mut self.records
    }

    /// Merges the nodes of other into itself
    pub fn merge(&mut self, other: Node) {
        let mut nodes = vec![(Vec::<Label>::new(), other)];

        while let Some((insert_path, node)) = nodes.pop() {
            if !node.records.is_empty() {
                let mut self_node = &mut *self;
                for label in &insert_path {
                    self_node = self_node.insert(label.clone());
                }
                for (_, record_set) in node.records {
                    for record in record_set {
                        self_node.add_record(record);
                    }
                }
            }

            for (label, child) in node.children {
                let mut insert_path = insert_path.clone();
                insert_path.push(label);
                nodes.push((insert_path, child))
            }
        }
    }
}
