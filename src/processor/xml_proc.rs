//! XML structured processor.
//!
//! Uses `quick-xml` to parse and rewrite XML, preserving the document
//! structure, attributes, and non-matched content.
//!
//! # Key Paths
//!
//! Element paths are slash-separated: `database/password`. Attributes
//! are expressed as `element/@attr` (e.g. `connection/@host`).
//!
//! For simplicity this processor tracks the element stack and matches
//! text content of elements and attribute values against field rules.

use crate::error::{Result, SanitizeError};
use crate::processor::limits::{DEFAULT_INPUT_SIZE, XML_DEPTH};
use crate::processor::{find_matching_rule, replace_value, FileTypeProfile, Processor};
use crate::store::MappingStore;
use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use std::io::Cursor;

/// Structured processor for XML files.
pub struct XmlProcessor;

impl Processor for XmlProcessor {
    fn name(&self) -> &'static str {
        "xml"
    }

    fn can_handle(&self, content: &[u8], profile: &FileTypeProfile) -> bool {
        if profile.processor == "xml" {
            return true;
        }
        let trimmed = content
            .iter()
            .copied()
            .skip_while(|b| b.is_ascii_whitespace())
            .take(5)
            .collect::<Vec<u8>>();
        trimmed.starts_with(b"<?xml") || trimmed.starts_with(b"<")
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        // F-04 fix: enforce input size limit.
        if content.len() > DEFAULT_INPUT_SIZE {
            return Err(SanitizeError::InputTooLarge {
                size: content.len(),
                limit: DEFAULT_INPUT_SIZE,
            });
        }

        // Security: quick-xml disables external entity expansion by default,
        // so XXE attacks are not possible with this configuration.
        let mut reader = Reader::from_reader(content);
        reader.trim_text(false);

        let mut writer = Writer::new(Cursor::new(Vec::new()));
        let mut element_stack: Vec<String> = Vec::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    element_stack.push(name.clone());

                    if element_stack.len() > XML_DEPTH {
                        return Err(SanitizeError::RecursionDepthExceeded(format!(
                            "XML element depth exceeds limit of {XML_DEPTH}"
                        )));
                    }

                    // Process attributes.
                    let current_path = element_stack.join("/");
                    let new_elem = process_attributes(e, &current_path, profile, store)?;
                    writer
                        .write_event(Event::Start(new_elem))
                        .map_err(|e| SanitizeError::IoError(format!("XML write error: {}", e)))?;
                }
                Ok(Event::End(ref e)) => {
                    writer
                        .write_event(Event::End(e.clone()))
                        .map_err(|e| SanitizeError::IoError(format!("XML write error: {}", e)))?;
                    element_stack.pop();
                }
                Ok(Event::Empty(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let path = if element_stack.is_empty() {
                        name.clone()
                    } else {
                        format!("{}/{}", element_stack.join("/"), name)
                    };
                    let new_elem = process_attributes(e, &path, profile, store)?;
                    writer
                        .write_event(Event::Empty(new_elem))
                        .map_err(|e| SanitizeError::IoError(format!("XML write error: {}", e)))?;
                }
                Ok(Event::Text(ref e)) => {
                    let current_path = element_stack.join("/");
                    if let Some(rule) = find_matching_rule(&current_path, profile) {
                        let text = e.unescape().map_err(|e| SanitizeError::ParseError {
                            format: "XML".into(),
                            message: format!("XML decode error: {}", e),
                        })?;
                        let replaced = replace_value(&text, rule, store)?;
                        writer
                            .write_event(Event::Text(BytesText::new(&replaced)))
                            .map_err(|e| {
                                SanitizeError::IoError(format!("XML write error: {}", e))
                            })?;
                    } else {
                        writer.write_event(Event::Text(e.clone())).map_err(|e| {
                            SanitizeError::IoError(format!("XML write error: {}", e))
                        })?;
                    }
                }
                Ok(Event::Eof) => break,
                Ok(e) => {
                    writer
                        .write_event(e)
                        .map_err(|er| SanitizeError::IoError(format!("XML write error: {}", er)))?;
                }
                Err(e) => {
                    return Err(SanitizeError::ParseError {
                        format: "XML".into(),
                        message: format!("XML parse error: {}", e),
                    });
                }
            }
            buf.clear();
        }

        let result = writer.into_inner().into_inner();
        Ok(result)
    }
}

/// Process attributes of an element, replacing matched ones.
fn process_attributes(
    elem: &BytesStart<'_>,
    element_path: &str,
    profile: &FileTypeProfile,
    store: &MappingStore,
) -> Result<BytesStart<'static>> {
    let name = elem.name();
    let mut new_elem = BytesStart::new(String::from_utf8_lossy(name.as_ref()).to_string());

    for attr_result in elem.attributes() {
        let attr = attr_result.map_err(|e| SanitizeError::ParseError {
            format: "XML".into(),
            message: format!("XML attribute error: {}", e),
        })?;
        let attr_key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        let attr_path = format!("{}/@{}", element_path, attr_key);

        if let Some(rule) = find_matching_rule(&attr_path, profile) {
            let attr_value = attr
                .unescape_value()
                .map_err(|e| SanitizeError::ParseError {
                    format: "XML".into(),
                    message: format!("XML attr decode error: {}", e),
                })?;
            let replaced = replace_value(&attr_value, rule, store)?;
            new_elem.push_attribute((attr_key.as_str(), replaced.as_str()));
        } else {
            let attr_value = attr
                .unescape_value()
                .map_err(|e| SanitizeError::ParseError {
                    format: "XML".into(),
                    message: format!("XML attr decode error: {}", e),
                })?;
            new_elem.push_attribute((attr_key.as_str(), attr_value.as_ref()));
        }
    }

    Ok(new_elem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::generator::HmacGenerator;
    use crate::processor::profile::FieldRule;
    use std::sync::Arc;

    fn make_store() -> MappingStore {
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        MappingStore::new(gen, None)
    }

    #[test]
    fn basic_xml_text_replacement() {
        let store = make_store();
        let proc = XmlProcessor;

        let content =
            b"<config><database><password>s3cret</password><port>5432</port></database></config>";
        let profile = FileTypeProfile::new(
            "xml",
            vec![FieldRule::new("config/database/password")
                .with_category(Category::Custom("pw".into()))],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();

        assert!(!out.contains("s3cret"));
        assert!(out.contains("<port>5432</port>"));
    }

    #[test]
    fn xml_attribute_replacement() {
        let store = make_store();
        let proc = XmlProcessor;

        let content = b"<config><connection host=\"db.corp.com\" port=\"5432\"/></config>";
        let profile = FileTypeProfile::new(
            "xml",
            vec![FieldRule::new("config/connection/@host").with_category(Category::Hostname)],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();

        assert!(!out.contains("db.corp.com"));
        assert!(out.contains("5432"));
    }
}
