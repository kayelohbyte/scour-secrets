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
use crate::processor::{
    edit_token, find_matching_rule, replace_value, FileTypeProfile, Processor, Replacement,
};
use crate::store::MappingStore;
use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use std::io::Cursor;

/// Scan a start/empty-tag's raw bytes (`<el a="v" b='w'/>`) for each attribute's
/// **value** byte range (the content between the quotes), in source order.
///
/// XML attribute values cannot contain their own unescaped delimiter quote, so
/// locating the closing quote is unambiguous. Returns ranges relative to `tag`.
fn scan_attr_value_spans(tag: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut spans = Vec::new();
    let mut i = 0;
    // Skip `<`, optional `/`, and the element name (up to whitespace or `>`/`/`).
    while i < tag.len() && (tag[i] == b'<' || tag[i] == b'/' || tag[i] == b'?') {
        i += 1;
    }
    while i < tag.len() && !tag[i].is_ascii_whitespace() && tag[i] != b'>' && tag[i] != b'/' {
        i += 1;
    }
    // Walk attributes: name = (?:")value(?:") | name = '...'.
    while i < tag.len() {
        while i < tag.len() && tag[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= tag.len() || tag[i] == b'>' || tag[i] == b'/' || tag[i] == b'?' {
            break;
        }
        // attribute name
        while i < tag.len() && tag[i] != b'=' && !tag[i].is_ascii_whitespace() && tag[i] != b'>' {
            i += 1;
        }
        while i < tag.len() && tag[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= tag.len() || tag[i] != b'=' {
            continue;
        }
        i += 1; // '='
        while i < tag.len() && tag[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= tag.len() || (tag[i] != b'"' && tag[i] != b'\'') {
            continue;
        }
        let quote = tag[i];
        i += 1;
        let val_start = i;
        while i < tag.len() && tag[i] != quote {
            i += 1;
        }
        spans.push(val_start..i);
        if i < tag.len() {
            i += 1; // closing quote
        }
    }
    spans
}

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
                    writer.write_event(Event::Start(new_elem)).map_err(|e| {
                        SanitizeError::IoError(std::io::Error::other(format!(
                            "XML write error: {e}"
                        )))
                    })?;
                }
                Ok(Event::End(ref e)) => {
                    writer.write_event(Event::End(e.clone())).map_err(|e| {
                        SanitizeError::IoError(std::io::Error::other(format!(
                            "XML write error: {e}"
                        )))
                    })?;
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
                    writer.write_event(Event::Empty(new_elem)).map_err(|e| {
                        SanitizeError::IoError(std::io::Error::other(format!(
                            "XML write error: {e}"
                        )))
                    })?;
                }
                Ok(Event::Text(ref e)) => {
                    let current_path = element_stack.join("/");
                    if let Some(rule) = find_matching_rule(&current_path, profile) {
                        let text = e.unescape().map_err(|e| SanitizeError::ParseError {
                            format: "XML".into(),
                            message: format!("XML decode error: {}", e),
                        })?;
                        let replaced = replace_value(&text, rule, store, "xml")?;
                        writer
                            .write_event(Event::Text(BytesText::new(&replaced)))
                            .map_err(|e| {
                                SanitizeError::IoError(std::io::Error::other(format!(
                                    "XML write error: {e}"
                                )))
                            })?;
                    } else {
                        writer.write_event(Event::Text(e.clone())).map_err(|e| {
                            SanitizeError::IoError(std::io::Error::other(format!(
                                "XML write error: {e}"
                            )))
                        })?;
                    }
                }
                Ok(Event::Eof) => break,
                Ok(e) => {
                    writer.write_event(e).map_err(|er| {
                        SanitizeError::IoError(std::io::Error::other(format!(
                            "XML write error: {er}"
                        )))
                    })?;
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

    /// Span-based redaction: walk the document with `quick-xml`, recording an
    /// edit for each matched element-text and attribute value at its exact
    /// source byte span. Element text spans come from `buffer_position()`;
    /// attribute value spans are located within each tag's bytes (using
    /// quick-xml for the unescaped values and key/path matching). Structure,
    /// comments, and unrelated bytes are preserved, and values are hit as
    /// written so escaped/entity-encoded content never leaks.
    fn process_to_edits(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Option<Vec<Replacement>>> {
        if content.len() > DEFAULT_INPUT_SIZE {
            return Err(SanitizeError::InputTooLarge {
                size: content.len(),
                limit: DEFAULT_INPUT_SIZE,
            });
        }
        let mut reader = Reader::from_reader(content);
        reader.trim_text(false);
        let mut edits = Vec::new();
        let mut stack: Vec<String> = Vec::new();
        let mut buf = Vec::new();

        loop {
            let before = reader.buffer_position();
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                    stack.push(name);
                    if stack.len() > XML_DEPTH {
                        return Err(SanitizeError::RecursionDepthExceeded(format!(
                            "XML element depth exceeds limit of {XML_DEPTH}"
                        )));
                    }
                    let path = stack.join("/");
                    collect_attr_edits(
                        &e,
                        content,
                        before,
                        reader.buffer_position(),
                        &path,
                        profile,
                        store,
                        &mut edits,
                    )?;
                }
                Ok(Event::Empty(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                    let path = if stack.is_empty() {
                        name
                    } else {
                        format!("{}/{name}", stack.join("/"))
                    };
                    collect_attr_edits(
                        &e,
                        content,
                        before,
                        reader.buffer_position(),
                        &path,
                        profile,
                        store,
                        &mut edits,
                    )?;
                }
                Ok(Event::Text(e)) => {
                    let end = reader.buffer_position();
                    let path = stack.join("/");
                    let key = stack.last().map_or("", String::as_str);
                    let text = e.unescape().map_err(|e| SanitizeError::ParseError {
                        format: "XML".into(),
                        message: format!("XML decode error: {e}"),
                    })?;
                    if let Some(token) = edit_token(key, &path, &text, profile, store)? {
                        edits.push(Replacement {
                            start: before,
                            end,
                            value: xml_escape_token(&token),
                        });
                    }
                }
                Ok(Event::End(_)) => {
                    stack.pop();
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(e) => {
                    return Err(SanitizeError::ParseError {
                        format: "XML".into(),
                        message: format!("XML parse error: {e}"),
                    });
                }
            }
            buf.clear();
        }
        Ok(Some(edits))
    }
}

/// XML-escape a (safe-ASCII) token for insertion as text/attribute content.
/// Tokens contain no markup characters in practice, but escape defensively.
fn xml_escape_token(token: &str) -> String {
    token
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Emit edits for matched attribute values of a start/empty element. Uses
/// quick-xml for the unescaped values (the mapping-store key) and a byte scan of
/// the tag for the exact source spans, correlated in source order.
#[allow(clippy::too_many_arguments)]
fn collect_attr_edits(
    elem: &BytesStart<'_>,
    content: &[u8],
    tag_start: usize,
    tag_end: usize,
    element_path: &str,
    profile: &FileTypeProfile,
    store: &MappingStore,
    edits: &mut Vec<Replacement>,
) -> Result<()> {
    let tag_end = tag_end.min(content.len());
    let tag = &content[tag_start..tag_end];
    let value_spans = scan_attr_value_spans(tag);

    for (idx, attr_result) in elem.attributes().enumerate() {
        let attr = attr_result.map_err(|e| SanitizeError::ParseError {
            format: "XML".into(),
            message: format!("XML attribute error: {e}"),
        })?;
        let Some(span) = value_spans.get(idx) else {
            // Span scan and quick-xml disagreed on attribute count — skip
            // editing this attribute rather than risk a wrong splice.
            continue;
        };
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let attr_path = format!("{element_path}/@{key}");
        let value = attr
            .unescape_value()
            .map_err(|e| SanitizeError::ParseError {
                format: "XML".into(),
                message: format!("XML attr decode error: {e}"),
            })?;
        if let Some(token) = edit_token(&key, &attr_path, &value, profile, store)? {
            edits.push(Replacement {
                start: tag_start + span.start,
                end: tag_start + span.end,
                value: xml_escape_token(&token),
            });
        }
    }
    Ok(())
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
            let replaced = replace_value(&attr_value, rule, store, "xml")?;
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
    use std::fmt::Write as _;
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

    #[test]
    fn can_handle_xml_declaration() {
        let proc = XmlProcessor;
        let profile = FileTypeProfile::new("other", vec![]).with_extension(".txt");
        assert!(proc.can_handle(b"<?xml version=\"1.0\"?><root/>", &profile));
    }

    #[test]
    fn can_handle_bare_tag() {
        let proc = XmlProcessor;
        let profile = FileTypeProfile::new("other", vec![]).with_extension(".txt");
        assert!(proc.can_handle(b"<root><child/></root>", &profile));
    }

    #[test]
    fn can_handle_by_profile_name() {
        let proc = XmlProcessor;
        let profile = FileTypeProfile::new("xml", vec![]).with_extension(".xml");
        assert!(proc.can_handle(b"not xml at all", &profile));
    }

    #[test]
    fn can_handle_rejects_plaintext() {
        let proc = XmlProcessor;
        let profile = FileTypeProfile::new("json", vec![]).with_extension(".json");
        assert!(!proc.can_handle(b"just some plain text", &profile));
    }

    #[test]
    fn empty_element_attributes_replaced() {
        let store = make_store();
        let proc = XmlProcessor;
        let content = b"<config><server host=\"prod.corp.com\" port=\"443\"/></config>";
        let profile = FileTypeProfile::new(
            "xml",
            vec![FieldRule::new("config/server/@host").with_category(Category::Hostname)],
        );
        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(!out.contains("prod.corp.com"));
        assert!(out.contains("443"));
    }

    #[test]
    fn empty_element_at_root_level() {
        let store = make_store();
        let proc = XmlProcessor;
        let content = b"<server host=\"root.corp.com\"/>";
        let profile = FileTypeProfile::new(
            "xml",
            vec![FieldRule::new("server/@host").with_category(Category::Hostname)],
        );
        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(!out.contains("root.corp.com"));
        // Non-secret structure preserved: element name and attribute key remain.
        assert!(out.contains("<server"));
        assert!(out.contains("host="));
    }

    #[test]
    fn unmatched_attributes_pass_through() {
        let store = make_store();
        let proc = XmlProcessor;
        let content = b"<config><db host=\"db.corp.com\" port=\"5432\"/></config>";
        let profile = FileTypeProfile::new("xml", vec![]); // no field rules
        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(out.contains("db.corp.com"));
        assert!(out.contains("5432"));
    }

    #[test]
    fn other_xml_events_pass_through() {
        let store = make_store();
        let proc = XmlProcessor;
        let content = b"<?xml version=\"1.0\"?><!-- comment --><root><child>value</child></root>";
        let profile = FileTypeProfile::new("xml", vec![]);
        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(out.contains("value"));
    }

    #[test]
    fn depth_limit_exceeded_returns_error() {
        let store = make_store();
        let proc = XmlProcessor;
        // Build XML that exceeds XML_DEPTH (256) levels of nesting.
        let open: String = (0..260).fold(String::new(), |mut s, i| {
            write!(s, "<l{i}>").unwrap();
            s
        });
        let close: String = (0..260).rev().fold(String::new(), |mut s, i| {
            write!(s, "</l{i}>").unwrap();
            s
        });
        let content = format!("{open}secret{close}");
        let profile = FileTypeProfile::new("xml", vec![]);
        let err = proc
            .process(content.as_bytes(), &profile, &store)
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::SanitizeError::RecursionDepthExceeded(_)
        ));
    }

    /// Edit-mode redacts element text and attribute values — including
    /// entity-encoded content — preserving structure and non-matched values.
    #[test]
    fn edits_redact_text_attr_and_entities() {
        let store = make_store();
        let proc = XmlProcessor;
        let content = b"<c><db pw=\"a&lt;b-SEC1\" host=\"keep\"/><t>tok-SEC2</t><k>ok</k></c>";
        let profile = FileTypeProfile::new(
            "xml",
            vec![
                FieldRule::new("c/db/@pw").with_category(Category::Custom("k".into())),
                FieldRule::new("c/t").with_category(Category::Custom("k".into())),
            ],
        );
        let edits = proc
            .process_to_edits(content, &profile, &store)
            .unwrap()
            .unwrap();
        let out = crate::processor::apply_edits(content, edits);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("SEC1"), "entity-encoded attr leaked: {text}");
        assert!(!text.contains("SEC2"), "element text leaked: {text}");
        assert!(
            text.contains("host=\"keep\""),
            "non-matched attr changed: {text}"
        );
        assert!(
            text.contains("<k>ok</k>"),
            "non-matched text changed: {text}"
        );
    }
}
