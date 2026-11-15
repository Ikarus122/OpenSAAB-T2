// SPDX-License-Identifier: MPL-2.0
//! K-line (ISO 14230 KWP2000, OBD pin 7) through the vLinker MC+ for the Tech 2's own
//! KW2000 link (VCI protocol 0x1308). The guest firmware builds every frame (format,
//! target, source, data, checksum); this side only re-addresses it for ELM (`ATSH`) and
//! hands the raw reply frame back.
//!
//! Vehicle-checked on a 2006 9-5 (DICE, address 0x41): `ATSP5`, `ATKW0`, `ATAT1`, `ATST96`,
//! `ATSH8041F1` gives `BUS INIT: ...OK`, `3E` -> `7E`, `1A90` -> VIN.
//!
//! Scope limits, stated rather than hidden:
//! - Read-only: identification, data/DTC reads, tester present and start/stop
//!   communication pass; anything else is refused without being sent.
//! - The ELM performs the fast init itself on the first request.
//! - One final reply frame is returned per request ("response pending" frames are skipped).
use super::Link;
use std::{path::Path, time::Duration};

/// VCI link protocol number the original firmware gives KWP2000 on K-line.
pub const KLINE_PROTOCOL_KW2000: u16 = 0x1308;

const KLINE_SETUP: [&str; 5] = ["ATH1", "ATSP5", "ATKW0", "ATAT1", "ATST96"];

#[derive(Debug, PartialEq)]
pub(crate) struct Frame<'a> {
    pub format: u8,
    pub target: u8,
    pub source: u8,
    pub data: &'a [u8],
}

pub(crate) fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |a, v| a.wrapping_add(*v))
}

/// Header length (format, target, source and optional length byte) and data length.
fn layout(bytes: &[u8]) -> Option<(usize, usize)> {
    let format = *bytes.first()?;
    if format & 0x80 == 0 || bytes.len() < 3 {
        return None;
    }
    match (format & 0x3f) as usize {
        0 => Some((4, *bytes.get(3)? as usize)),
        n => Some((3, n)),
    }
}

/// Splits a complete guest frame (with checksum) into its parts.
pub(crate) fn split(frame: &[u8]) -> Result<Frame<'_>, String> {
    let (header, n) = layout(frame).ok_or("KWP frame without address bytes")?;
    if frame.len() != header + n + 1 {
        return Err(format!("KWP frame length mismatch: {frame:02X?}"));
    }
    let (body, cs) = frame.split_at(frame.len() - 1);
    if checksum(body) != cs[0] {
        return Err(format!("KWP frame checksum mismatch: {frame:02X?}"));
    }
    Ok(Frame {
        format: frame[0],
        target: frame[1],
        source: frame[2],
        data: &body[header..],
    })
}

/// Services that only read or keep the session alive.
pub(crate) fn read_only(data: &[u8]) -> bool {
    match data {
        [0x81] | [0x82] | [0x3E] | [0x3E, _] | [0x20] | [0x10, 0x81] => true,
        [0x1A, ..] | [0x21, ..] | [0x22, ..] | [0x12, ..] | [0x13, ..] | [0x17, ..] | [0x18, ..] => true,
        _ => false,
    }
}

/// Converts ELM output lines into complete raw frames (checksum included) sent by `ecu`
/// to `tester`. Status lines give no frame.
pub(crate) fn parse_reply(
    lines: &[String],
    tester: u8,
    ecu: u8,
    functional: bool,
) -> Result<Vec<Vec<u8>>, String> {
    let mut frames = vec![];
    for line in lines {
        let mut text = line.trim();
        if let Some(rest) = text.strip_prefix("BUS INIT:") {
            match rest.trim().strip_prefix("...OK").or_else(|| rest.trim().strip_prefix("OK")) {
                Some(after) => text = after.trim(),
                None => continue,
            }
        }
        let tokens: Vec<_> = text.split_whitespace().collect();
        if tokens.is_empty()
            || !tokens
                .iter()
                .all(|t| t.len() == 2 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            continue;
        }
        let mut bytes: Vec<u8> = tokens
            .iter()
            .map(|t| u8::from_str_radix(t, 16).unwrap())
            .collect();
        let Some((header, n)) = layout(&bytes) else { continue };
        if bytes.len() == header + n {
            bytes.push(checksum(&bytes));
        } else if bytes.len() != header + n + 1 {
            return Err(format!("ELM K-line frame length mismatch: {line}"));
        }
        if bytes[1] != tester || (!functional && bytes[2] != ecu) {
            continue;
        }
        let data = &bytes[header..bytes.len() - 1];
        if data.len() == 3 && data[0] == 0x7F && data[2] == 0x78 {
            continue;
        }
        frames.push(bytes);
    }
    Ok(frames)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02X}")).collect()
}

/// Exclusive K-line session on the vLinker byte bridge.
pub struct KlineSession {
    link: Link,
    header: Option<[u8; 3]>,
}

impl KlineSession {
    pub fn start(token: &str, directory: &Path) -> Result<Self, String> {
        if token.len() != 32 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid vLinker owner token".into());
        }
        let mut link = Link::open(token, directory)?;
        link.identify()?;
        for cmd in KLINE_SETUP {
            link.exact(cmd, "OK")?;
        }
        link.configured = true;
        link.record(serde_json::json!({"kline_setup_complete":true,"protocol":"ISO 14230 fast init (ATSP5)","pin":7,"policy":"read-only"}))?;
        Ok(Self { link, header: None })
    }

    /// Sends one guest frame and returns the reply frames. Refused or unanswered requests
    /// return no frame; the guest then times out as with a silent module.
    pub fn exchange(&mut self, frame: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let f = split(frame)?;
        self.link
            .record(serde_json::json!({"guest_kline_tx":hex(frame)}))?;
        if !read_only(f.data) {
            self.link
                .record(serde_json::json!({"kline_refused_not_read_only":hex(f.data)}))?;
            return Ok(vec![]);
        }
        let header = [f.format & 0xC0, f.target, f.source];
        if self.header != Some(header) {
            self.link.exact(&format!("ATSH{}", hex(&header)), "OK")?;
            self.header = Some(header);
        }
        let lines = self
            .link
            .reply_within(&hex(f.data), Duration::from_secs(6))?;
        let frames = parse_reply(&lines, f.source, f.target, f.format & 0x40 != 0)?;
        self.link.record(serde_json::json!({"kline_rx_lines":lines,"frames":frames.iter().map(|v|hex(v)).collect::<Vec<_>>()}))?;
        Ok(frames)
    }
}

impl Drop for KlineSession {
    fn drop(&mut self) {
        let (events, _unused) = std::sync::mpsc::sync_channel(1);
        self.link.cleanup(&events);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn splits_guest_frame_and_checks_checksum() {
        let f = [0x82, 0x41, 0xF1, 0x1A, 0x90, 0x00];
        let mut good = f.to_vec();
        good[5] = checksum(&f[..5]);
        let s = split(&good).unwrap();
        assert_eq!((s.format, s.target, s.source, s.data), (0x82, 0x41, 0xF1, &[0x1A, 0x90][..]));
        good[5] ^= 1;
        assert!(split(&good).is_err());
        assert!(split(&[0x02, 0x1A, 0x90, 0xAC]).is_err());
    }

    #[test]
    fn length_byte_form_is_supported() {
        let mut f = vec![0x80, 0x41, 0xF1, 0x01, 0x3E];
        f.push(checksum(&f));
        assert_eq!(split(&f).unwrap().data, &[0x3E]);
    }

    #[test]
    fn read_only_policy() {
        assert!(read_only(&[0x1A, 0x90]));
        assert!(read_only(&[0x3E]));
        assert!(read_only(&[0x81]));
        assert!(!read_only(&[0x27, 0x01]));
        assert!(!read_only(&[0x14, 0xFF, 0x00]));
        assert!(!read_only(&[0x31, 0x01]));
        assert!(!read_only(&[0x10, 0x85]));
        assert!(!read_only(&[0x3B, 0x90]));
    }

    #[test]
    fn reply_adds_missing_checksum_and_filters_other_modules() {
        let got = parse_reply(
            &lines(&["BUS INIT: ...OK", "81 F1 41 7E", "81 F1 11 7E", "NO DATA"]),
            0xF1,
            0x41,
            false,
        )
        .unwrap();
        assert_eq!(got, vec![vec![0x81, 0xF1, 0x41, 0x7E, 0x31]]);
    }

    #[test]
    fn reply_keeps_shown_checksum_and_skips_pending() {
        let got = parse_reply(
            &lines(&["83 F1 41 7F 1A 78 C6", "82 F1 41 5A 90 9E"]),
            0xF1,
            0x41,
            false,
        )
        .unwrap();
        assert_eq!(got, vec![vec![0x82, 0xF1, 0x41, 0x5A, 0x90, 0x9E]]);
    }

    #[test]
    fn status_lines_give_no_frame() {
        for s in ["NO DATA", "BUS INIT: ...ERROR", "?", "UNABLE TO CONNECT", "STOPPED"] {
            assert!(parse_reply(&lines(&[s]), 0xF1, 0x41, false).unwrap().is_empty());
        }
    }
}
