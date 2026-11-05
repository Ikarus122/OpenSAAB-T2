// SPDX-License-Identifier: MPL-2.0
//! Passive request intent counters. These never authorize, transmit or retry a request.
use crate::candi_cpu::CanFrame;
use serde_json::{json, Value};

pub const REQUESTS: &[&str] = &[
    "unknown",
    "read",
    "security_seed",
    "security_key",
    "write_data",
    "device_control",
    "download",
    "other",
];

/// Inspect only an original single/first ISO-TP frame on a known diagnostic route.
/// Never interpret continuation data (which may contain a VIN or key) as a service.
pub fn request(frame: &CanFrame) -> &'static str {
    if frame.validate().is_err()
        || frame.extended
        || frame.rtr
        || !(frame.id == 0x101
            || (0x240..=0x25f).contains(&frame.id)
            || (0x7e0..=0x7e7).contains(&frame.id))
    {
        return "unknown";
    }
    let data = frame.data.as_slice();
    let offset = usize::from(data.first() == Some(&0xfe));
    let Some(&pci) = data.get(offset) else {
        return "unknown";
    };
    let (start, end) = match pci >> 4 {
        0 if pci > 0 && offset + 1 + usize::from(pci) <= data.len() => {
            (offset + 1, offset + 1 + usize::from(pci))
        }
        1 if data.len() >= offset + 4
            && ((usize::from(pci & 15) << 8) | usize::from(data[offset + 1])) > 7 =>
        {
            (offset + 2, data.len())
        }
        _ => return "unknown",
    };
    let body = &data[start..end];
    match body.first() {
        Some(0x27) => match body.get(1) {
            Some(n) if n % 2 == 1 => "security_seed",
            Some(_) => "security_key",
            None => "unknown",
        },
        Some(0x2e | 0x3b) => "write_data",
        Some(0xae | 0x2f | 0x31) => "device_control",
        Some(0x34..=0x37) => "download",
        Some(0x19 | 0x1a | 0x21 | 0x22 | 0x23 | 0x3e | 0xaa) => "read",
        Some(_) => "other",
        None => "unknown",
    }
}

#[derive(Clone, Default)]
pub struct Progress {
    intents: u64,
    queued: u64,
    potential_changes: u64,
    security_keys: u64,
    last_request: Option<&'static str>,
}
impl Progress {
    pub fn observed(&mut self, frame: &CanFrame) {
        self.intents = self.intents.saturating_add(1);
        let kind = request(frame);
        if kind != "unknown" {
            self.last_request = Some(kind);
        }
        if matches!(kind, "write_data" | "device_control" | "download") {
            self.potential_changes = self.potential_changes.saturating_add(1);
        }
        if kind == "security_key" {
            self.security_keys = self.security_keys.saturating_add(1);
        }
    }
    pub fn queued(&mut self) {
        self.queued = self.queued.saturating_add(1);
    }
    pub fn snapshot(&self) -> Value {
        json!({"request_intents":self.intents,"requests_queued":self.queued,
            "potential_change_intents":self.potential_changes,"security_key_intents":self.security_keys,
            "last_request":self.last_request.unwrap_or("unknown")})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn f(data: &[u8]) -> CanFrame {
        CanFrame {
            id: 0x7e0,
            extended: false,
            rtr: false,
            dlc: data.len() as u8,
            data: data.to_vec(),
        }
    }
    #[test]
    fn parses_headers_without_interpreting_secret_continuations_or_padding() {
        assert_eq!(request(&f(&[2, 0x27, 1, 0, 0, 0, 0, 0])), "security_seed");
        assert_eq!(
            request(&f(&[4, 0x27, 2, 0x12, 0x34, 0, 0, 0])),
            "security_key"
        );
        assert_eq!(
            request(&f(&[0x10, 0x14, 0x3b, 0x90, 1, 2, 3, 4])),
            "write_data"
        );
        assert_eq!(
            request(&f(&[0xfe, 2, 0x27, 0x0c, 0, 0, 0, 0])),
            "security_key"
        );
        for data in [
            &[0x21, 0x27, 2, 0x3b, 0x90, 0, 0, 0][..],
            &[0x30, 0, 0, 0x27, 2][..],
            &[1, 0x27, 2][..],
            &[0x10, 1, 0x3b, 0x90][..],
        ] {
            assert_eq!(request(&f(data)), "unknown");
        }
        let mut unrelated = f(&[2, 0xae, 0x60]);
        unrelated.id = 0x500;
        assert_eq!(request(&unrelated), "unknown");
    }
    #[test]
    fn later_key_failure_retains_earlier_intents_without_claiming_commit() {
        let mut p = Progress::default();
        for bytes in [&[3, 0x3b, 0x90, 1][..], &[3, 0x3b, 0x63, 1][..]] {
            p.observed(&f(bytes));
            p.queued();
        }
        p.observed(&f(&[4, 0x27, 2, 0x12, 0x34]));
        assert_eq!(
            p.snapshot(),
            json!({"request_intents":3,"requests_queued":2,"potential_change_intents":2,"security_key_intents":1,"last_request":"security_key"})
        );
        assert!(!p.snapshot().to_string().contains("1234"));
    }
}
