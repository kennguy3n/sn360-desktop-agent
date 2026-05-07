//! Parser for Windows Event Log XML fragments produced by `EvtRender`.
//!
//! Kept target-agnostic so the unit tests can run on any host. The
//! parser intentionally avoids a full XML dependency: event XML is
//! well-formed and regular enough that a small hand-rolled scanner is
//! adequate for the handful of fields we care about.

/// Turn an event log XML fragment into a compact, human-readable text
/// representation suitable for publishing on the event bus.
///
/// The output contains the most useful System-level fields (Provider,
/// EventID, Level, TimeCreated, Channel, Computer) followed by every
/// `<Data>` element under `<EventData>`. Returns the raw XML if no
/// recognised fields are found, so we never drop data.
pub fn parse_event_message(xml: &str) -> String {
    let mut parts: Vec<String> = Vec::new();

    let render_element = |parts: &mut Vec<String>, label: &str, text: Option<ElementText>| {
        if let Some(t) = text {
            parts.push(format!("{}: {}", label, t.for_display()));
        }
    };

    if let Some(v) = extract_attr(xml, "Provider", "Name") {
        parts.push(format!("Provider: {}", decode_entities(&v)));
    }
    render_element(&mut parts, "EventID", extract_element_text(xml, "EventID"));
    render_element(&mut parts, "Level", extract_element_text(xml, "Level"));
    if let Some(v) = extract_attr(xml, "TimeCreated", "SystemTime") {
        parts.push(format!("TimeCreated: {}", decode_entities(&v)));
    }
    render_element(&mut parts, "Channel", extract_element_text(xml, "Channel"));
    render_element(
        &mut parts,
        "Computer",
        extract_element_text(xml, "Computer"),
    );

    for (name, value) in extract_data_elements(xml) {
        let display = value.for_display();
        match name {
            Some(n) => parts.push(format!("Data [{}]: {}", n, display)),
            None => parts.push(format!("Data: {}", display)),
        }
    }

    if parts.is_empty() {
        xml.to_string()
    } else {
        parts.join("\n")
    }
}

/// Text extracted from an element, along with whether it came from a
/// `<![CDATA[...]]>` section. CDATA is literal character data per the
/// XML spec, so entity references inside it are *not* decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ElementText {
    value: String,
    is_cdata: bool,
}

impl ElementText {
    fn for_display(&self) -> String {
        let trimmed = self.value.trim();
        if self.is_cdata {
            trimmed.to_string()
        } else {
            decode_entities(trimmed)
        }
    }
}

/// Extract the text content of the first `<tag ...>content</tag>`.
/// Returns None for self-closing tags.
///
/// Text inside `<![CDATA[...]]>` sections is returned verbatim
/// (without the CDATA wrapper).
fn extract_element_text(xml: &str, tag: &str) -> Option<ElementText> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    // Walk forward through every occurrence of `<tag` iteratively so
    // that prefix matches (e.g. `EventID` is a prefix of
    // `EventIDQualifiers`) are skipped without recursion.
    let mut offset = 0usize;
    while offset < xml.len() {
        let rel = xml[offset..].find(&open)?;
        let start = offset + rel;
        let after_open = &xml[start + open.len()..];

        let next = after_open.chars().next()?;
        if !matches!(next, ' ' | '\t' | '\n' | '\r' | '>' | '/') {
            offset = start + open.len();
            continue;
        }

        let tag_end = after_open.find('>')?;
        if after_open[..tag_end].ends_with('/') {
            return None;
        }
        let content_start = start + open.len() + tag_end + 1;
        let rel_close = xml[content_start..].find(&close)?;
        let raw = &xml[content_start..content_start + rel_close];
        return Some(strip_cdata(raw));
    }
    None
}

/// Extract the value of `attr` on the first `<tag ...>` opening tag.
fn extract_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{}", tag);

    let mut offset = 0usize;
    while offset < xml.len() {
        let rel = xml[offset..].find(&open)?;
        let start = offset + rel;
        let after = &xml[start..];

        let next = after.as_bytes().get(open.len()).copied()?;
        if !matches!(next, b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/') {
            offset = start + open.len();
            continue;
        }

        let close = after.find('>')?;
        let tag_contents = &after[..close];
        return extract_attr_in_tag(tag_contents, attr);
    }
    None
}

/// Extract every `<Data>` element in document order, along with its
/// optional `Name` attribute. Handles both `<Data Name="x">value</Data>`
/// and self-closing `<Data Name="x"/>` forms.
fn extract_data_elements(xml: &str) -> Vec<(Option<String>, ElementText)> {
    let mut out = Vec::new();
    let mut cursor = 0;
    let open = "<Data";
    let close = "</Data>";

    while let Some(found) = xml[cursor..].find(open) {
        let tag_start = cursor + found;
        // Ensure we matched the whole element name, not a prefix.
        let after_tag = &xml[tag_start + open.len()..];
        let next = match after_tag.chars().next() {
            Some(c) => c,
            None => break,
        };
        if !matches!(next, ' ' | '\t' | '\n' | '\r' | '>' | '/') {
            cursor = tag_start + open.len();
            continue;
        }

        let tag_end_rel = match after_tag.find('>') {
            Some(i) => i,
            None => break,
        };
        let tag_contents = &after_tag[..tag_end_rel];
        let name = extract_attr_in_tag(tag_contents, "Name");

        let self_closing = tag_contents.ends_with('/');
        let value_start = tag_start + open.len() + tag_end_rel + 1;

        if self_closing {
            out.push((
                name,
                ElementText {
                    value: String::new(),
                    is_cdata: false,
                },
            ));
            cursor = value_start;
            continue;
        }

        let rel_close = match xml[value_start..].find(close) {
            Some(i) => i,
            None => break,
        };
        let value = strip_cdata(&xml[value_start..value_start + rel_close]);
        out.push((name, value));
        cursor = value_start + rel_close + close.len();
    }

    out
}

/// Extract the value of `attr` from the body of an opening tag
/// (the text between `<TagName` and `>`). Accepts either single or
/// double-quoted attribute values, matching the XML 1.0 grammar.
fn extract_attr_in_tag(tag_body: &str, attr: &str) -> Option<String> {
    let eq_marker = format!("{}=", attr);
    let mut search_from = 0usize;
    // Skip attribute names that end with `attr` as a suffix (e.g. the
    // request for `Name` should not match `FileName`).
    loop {
        let rel = tag_body[search_from..].find(&eq_marker)?;
        let eq_pos = search_from + rel;
        let preceding = tag_body.as_bytes().get(eq_pos.wrapping_sub(1)).copied();
        match preceding {
            Some(b) if b.is_ascii_alphanumeric() || b == b'-' || b == b':' || b == b'_' => {
                search_from = eq_pos + eq_marker.len();
                continue;
            }
            _ => {
                let value_start = eq_pos + eq_marker.len();
                let quote = tag_body.as_bytes().get(value_start).copied()?;
                if quote != b'"' && quote != b'\'' {
                    return None;
                }
                let rest = &tag_body[value_start + 1..];
                let end = rest.find(quote as char)?;
                return Some(rest[..end].to_string());
            }
        }
    }
}

/// Unwrap any surrounding `<![CDATA[...]]>` marker. If the slice is a
/// CDATA section the inner literal text is returned with `is_cdata =
/// true`; otherwise the original text is returned with `is_cdata =
/// false`. Callers use the flag to skip entity decoding on literal
/// CDATA content. Whitespace around the CDATA section is tolerated;
/// the caller still trims the result for display.
fn strip_cdata(raw: &str) -> ElementText {
    const OPEN: &str = "<![CDATA[";
    const CLOSE: &str = "]]>";
    let trimmed = raw.trim();
    if let Some(body) = trimmed.strip_prefix(OPEN) {
        if let Some(inner) = body.strip_suffix(CLOSE) {
            return ElementText {
                value: inner.to_string(),
                is_cdata: true,
            };
        }
    }
    ElementText {
        value: raw.to_string(),
        is_cdata: false,
    }
}

/// Decode the five XML predefined entities plus numeric character
/// references (`&#NN;`, `&#xHH;`). Unknown entities pass through
/// unchanged so we never drop data.
fn decode_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }

    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            // Copy the run of non-'&' bytes as a str slice so multi-byte
            // UTF-8 sequences are preserved. Widening bytes individually
            // to `char` would produce mojibake (e.g. 'é' -> 'Ã©').
            let start = i;
            while i < bytes.len() && bytes[i] != b'&' {
                i += 1;
            }
            out.push_str(&input[start..i]);
            continue;
        }
        // Find the terminating ';' within a reasonable window so we
        // don't consume arbitrarily large prefixes on malformed input.
        let end = match input[i + 1..].find(';') {
            Some(off) if off <= 16 => i + 1 + off,
            _ => {
                out.push('&');
                i += 1;
                continue;
            }
        };
        let entity = &input[i + 1..end];
        let replacement: Option<String> = match entity {
            "amp" => Some("&".to_string()),
            "lt" => Some("<".to_string()),
            "gt" => Some(">".to_string()),
            "quot" => Some("\"".to_string()),
            "apos" => Some("'".to_string()),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16)
                .ok()
                .and_then(char::from_u32)
                .map(|c| c.to_string()),
            e if e.starts_with('#') => e[1..]
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .map(|c| c.to_string()),
            _ => None,
        };
        match replacement {
            Some(s) => {
                out.push_str(&s);
                i = end + 1;
            }
            None => {
                out.push_str(&input[i..=end]);
                i = end + 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SECURITY_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime='2026-04-19T03:00:00.000000000Z'/>
    <EventRecordID>12345</EventRecordID>
    <Correlation/>
    <Execution ProcessID='624' ThreadID='724'/>
    <Channel>Security</Channel>
    <Computer>DESKTOP-ABC</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>SYSTEM</Data>
    <Data Name='SubjectDomainName'>NT AUTHORITY</Data>
    <Data Name='TargetUserName'>alice</Data>
    <Data Name='LogonType'>3</Data>
  </EventData>
</Event>"#;

    #[test]
    fn parses_provider_attribute() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("Provider: Microsoft-Windows-Security-Auditing"));
    }

    #[test]
    fn parses_event_id_text() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("EventID: 4624"));
    }

    #[test]
    fn parses_level_text() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("Level: 0"));
    }

    #[test]
    fn parses_time_created_attribute() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("TimeCreated: 2026-04-19T03:00:00.000000000Z"));
    }

    #[test]
    fn parses_channel_and_computer() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("Channel: Security"));
        assert!(msg.contains("Computer: DESKTOP-ABC"));
    }

    #[test]
    fn parses_named_data_elements() {
        let msg = parse_event_message(SAMPLE_SECURITY_XML);
        assert!(msg.contains("Data [SubjectUserName]: SYSTEM"));
        assert!(msg.contains("Data [TargetUserName]: alice"));
        assert!(msg.contains("Data [LogonType]: 3"));
    }

    #[test]
    fn ignores_prefix_matches_for_event_id() {
        let xml = r#"<Event>
            <System>
                <EventIDQualifiers>42</EventIDQualifiers>
                <EventID>1234</EventID>
            </System>
        </Event>"#;
        let msg = parse_event_message(xml);
        assert!(msg.contains("EventID: 1234"));
        // Make sure we did not pick up the Qualifiers value.
        assert!(!msg.contains("EventID: 42"));
    }

    #[test]
    fn handles_self_closing_data_elements() {
        let xml = r#"<Event><EventData>
            <Data Name='Empty'/>
            <Data Name='Filled'>value</Data>
        </EventData></Event>"#;
        let msg = parse_event_message(xml);
        assert!(msg.contains("Data [Empty]: "));
        assert!(msg.contains("Data [Filled]: value"));
    }

    #[test]
    fn handles_unnamed_data_elements() {
        let xml = r#"<Event><EventData>
            <Data>positional value</Data>
        </EventData></Event>"#;
        let msg = parse_event_message(xml);
        assert!(msg.contains("Data: positional value"));
    }

    #[test]
    fn returns_raw_xml_when_no_fields_match() {
        let xml = "<Something/>";
        let msg = parse_event_message(xml);
        assert_eq!(msg, xml);
    }

    #[test]
    fn handles_missing_optional_fields() {
        let xml = r#"<Event>
            <System>
                <EventID>1</EventID>
            </System>
        </Event>"#;
        let msg = parse_event_message(xml);
        assert!(msg.contains("EventID: 1"));
        assert!(!msg.contains("Level:"));
        assert!(!msg.contains("Channel:"));
    }

    #[test]
    fn decodes_predefined_xml_entities_in_data_values() {
        let xml = r#"<Event><EventData>
            <Data Name='Cmd'>echo &quot;hi&quot; &amp;&amp; exit 0</Data>
            <Data Name='Tag'>&lt;root/&gt;</Data>
        </EventData></Event>"#;
        let msg = parse_event_message(xml);
        assert!(
            msg.contains(r#"Data [Cmd]: echo "hi" && exit 0"#),
            "entities not decoded: {}",
            msg
        );
        assert!(msg.contains("Data [Tag]: <root/>"), "got: {}", msg);
    }

    #[test]
    fn decodes_numeric_character_references() {
        let xml = r#"<Event><EventData>
            <Data>A&#65;&#x42;</Data>
        </EventData></Event>"#;
        let msg = parse_event_message(xml);
        // &#65; -> 'A', &#x42; -> 'B'
        assert!(msg.contains("Data: AAB"), "got: {}", msg);
    }

    #[test]
    fn preserves_unknown_entities_verbatim() {
        let xml = r#"<Event><EventData>
            <Data>&unknown;&amp;</Data>
        </EventData></Event>"#;
        let msg = parse_event_message(xml);
        assert!(msg.contains("Data: &unknown;&"), "got: {}", msg);
    }

    #[test]
    fn unwraps_cdata_sections_in_data_elements() {
        // CDATA content is literal per the XML spec: the `&amp;`
        // inside the CDATA is five literal characters, not an
        // entity reference, so the output must preserve it verbatim.
        let xml = r#"<Event><EventData>
            <Data Name='Raw'><![CDATA[<html>&amp;payload</html>]]></Data>
        </EventData></Event>"#;
        let msg = parse_event_message(xml);
        assert!(
            msg.contains("Data [Raw]: <html>&amp;payload</html>"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn cdata_content_is_not_entity_decoded_in_system_field() {
        let xml = r#"<Event><System>
            <Channel><![CDATA[App&amp;Test]]></Channel>
        </System></Event>"#;
        let msg = parse_event_message(xml);
        assert!(msg.contains("Channel: App&amp;Test"), "got: {}", msg);
    }

    #[test]
    fn unwraps_cdata_in_system_field() {
        let xml = r#"<Event><System>
            <Channel><![CDATA[Application]]></Channel>
        </System></Event>"#;
        let msg = parse_event_message(xml);
        assert!(msg.contains("Channel: Application"), "got: {}", msg);
    }

    #[test]
    fn decode_entities_preserves_multibyte_utf8() {
        // An event that mixes non-ASCII text (café, 日本語, emoji) with an
        // XML entity must not get its multi-byte codepoints mangled.
        let xml = r#"<Event><EventData>
            <Data Name='User'>café &amp; 日本語 🎉</Data>
        </EventData></Event>"#;
        let msg = parse_event_message(xml);
        assert!(
            msg.contains("Data [User]: café & 日本語 🎉"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn iterative_prefix_match_does_not_stack_overflow() {
        // Many prefix-only tags before the real EventID. The old
        // recursive implementation would blow the stack on input
        // like this; the iterative version must still find `777`.
        let mut xml = String::from("<Event><System>");
        for _ in 0..10_000 {
            xml.push_str("<EventIDQualifiers>x</EventIDQualifiers>");
        }
        xml.push_str("<EventID>777</EventID></System></Event>");
        let msg = parse_event_message(&xml);
        assert!(msg.contains("EventID: 777"), "did not find real tag");
    }
}
