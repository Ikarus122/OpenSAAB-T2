// SPDX-License-Identifier: MPL-2.0
//! Shared classification of a live adapter stop, so every desktop shell shows the same
//! explanation instead of a blank or stale firmware frame. Input is the adapter error the
//! native link already received plus the last CAN transmission it submitted; nothing here
//! talks to hardware, retries, or invents an ECU reply. An unknown error stays "adapter_stopped".
use serde_json::{json, Value};
pub mod progress;

/// Fixed diagnostic labels only. Raw error text remains in the private local report.
pub fn cause(raw: &str) -> &'static str {
    if raw.contains("command guard blocked before")
        || raw.contains("command rejected by collection profile")
        || raw.contains("command/continuation gate rejected request")
        || raw.contains("session gate rejected request")
    {
        "local_policy_refusal"
    } else if disconnected(raw) {
        "adapter_disconnected"
    } else if raw.contains("checksum mismatch") {
        "nano_checksum_mismatch"
    } else if raw.contains("Nano")
        && [
            "delimiter",
            "escape",
            "Truncated Nano frame",
            "framing error",
        ]
        .iter()
        .any(|s| raw.contains(s))
    {
        "nano_framing_error"
    } else if raw.contains("opcode ") && raw.contains(": status ") {
        "nano_adapter_status"
    } else if raw.contains("deadline") || raw.to_ascii_lowercase().contains("timed out") {
        "transport_timeout"
    } else if raw.contains("write failed or was short") || raw.contains("serial short write") {
        "transport_write_failure"
    } else {
        "unclassified_adapter_error"
    }
}
const CAUSES: &[&str] = &[
    "local_policy_refusal",
    "adapter_disconnected",
    "nano_checksum_mismatch",
    "nano_framing_error",
    "nano_adapter_status",
    "transport_timeout",
    "transport_write_failure",
    "unclassified_adapter_error",
];

fn nano_status(raw: &str) -> Option<Value> {
    let (_, rest) = raw.split_once("opcode ")?;
    let (op, rest) = rest.split_once(": status ")?;
    let status = rest.get(..2)?;
    if op.len() != 2
        || !op
            .bytes()
            .chain(status.bytes())
            .all(|b| b.is_ascii_hexdigit())
        || rest
            .as_bytes()
            .get(2)
            .is_some_and(|b| !b.is_ascii_whitespace())
    {
        return None;
    }
    Some(
        json!({"opcode":u8::from_str_radix(op,16).ok()?,"status":u8::from_str_radix(status,16).ok()?}),
    )
}

/// Fits the deployed report schema's existing message field. Whitelist every value;
/// never copy raw adapter text, payloads or arbitrary local JSON into an upload.
pub fn support_summary(failure: &Value) -> Option<String> {
    let code = failure["cause"].as_str().filter(|s| CAUSES.contains(s))?;
    let p = &failure["request_progress"];
    let last = p["last_request"]
        .as_str()
        .filter(|s| progress::REQUESTS.contains(s))
        .unwrap_or("unknown");
    let count = |key: &str| {
        p[key]
            .as_u64()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".into())
    };
    let nano = &failure["nano_status"];
    let numeric = match (nano["opcode"].as_u64(), nano["status"].as_u64()) {
        (Some(op @ 0..=255), Some(status @ 0..=255)) => {
            format!("; adapter_opcode={op:02X}; adapter_status={status:02X}")
        }
        _ => String::new(),
    };
    Some(format!("cause={code}{numeric}; last_request_intent={last}; request_intents={}; requests_queued={}; potential_change_intents={}; security_key_intents={}; vehicle_state=unknown. Intents and queue acceptance do not prove transmission, ECU acceptance or persistence.",count("request_intents"),count("requests_queued"),count("potential_change_intents"),count("security_key_intents")))
}

pub fn policy_refusal(
    controller: usize,
    tx: &crate::candi_cpu::CanTransmission,
    profile: crate::adapters::common::policy::Profile,
) -> String {
    format!("VCX Nano command guard blocked before transport: controller={controller} request={} profile={profile:?}; no ECU rejection",progress::request(&tx.frame))
}

/// The last frame the emulated CANdi handed to the adapter before the stop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxContext {
    pub controller: usize,
    pub bus: &'static str,
    pub wake: bool,
    pub id: u32,
    pub dlc: u8,
}

impl TxContext {
    pub fn new(controller: usize, tx: &crate::candi_cpu::CanTransmission) -> Self {
        let bus = match crate::candi_transport::ROUTES
            .get(controller)
            .map(|r| r.bus)
        {
            Some(crate::candi_transport::PhysicalBus::HighSpeed) => "HighSpeed",
            Some(crate::candi_transport::PhysicalBus::Middle) => "Middle",
            Some(crate::candi_transport::PhysicalBus::SingleWire) => "SingleWire",
            None => "unknown",
        };
        TxContext {
            controller,
            bus,
            wake: tx.electrical.wake_control_selected(),
            id: tx.frame.id,
            dlc: tx.frame.dlc,
        }
    }
    fn is_single_wire_wake(&self) -> bool {
        self.bus == "SingleWire" && self.wake && self.id == 0x100 && self.dlc == 0
    }
}

const SW_WAKE_MESSAGE: &str = "The adapter could not complete the single-wire CAN wake-up request. The adapter connection worked, but this vehicle-network step did not complete.\n\nOn an ECM-only bench, a high-speed CAN VIN read can work while the original menus still need the low-speed bus. Check the single-wire CAN connection at diagnostic pin 1. ECU information and DTC reading have not been confirmed.";

fn transport_detail(raw: &str) -> Option<&'static str> {
    if raw.contains("Chipsoft opcode=000F status=001D") {
        Some("Chipsoft status 001D")
    } else if raw.contains("ERR_CAN_WRITE_TIMEOUT") {
        Some("J2534 ERR_CAN_WRITE_TIMEOUT")
    } else {
        None
    }
}

fn disconnected(raw: &str) -> bool {
    let l = raw.to_ascii_lowercase();
    [
        "err_device_not_connected",
        "no such device",
        "device not configured",
        "device disconnected",
        "device removed",
        "serial port closed",
    ]
    .iter()
    .any(|s| l.contains(s))
}

/// Classify one adapter stop. `raw` is the error text after "Native adapter stopped: ".
pub fn classify(raw: &str, last_tx: Option<&TxContext>) -> Value {
    let raw_short: String = raw.chars().take(300).collect();
    let tx = last_tx.map(|t| json!({"controller":t.controller,"bus":t.bus,"wake":t.wake,"id":format!("{:03X}",t.id),"dlc":t.dlc}));
    let out = |kind: &str, title: &str, message: String| json!({"schema":1,"kind":kind,"title":title,"message":message,"adapter_error":raw_short,"cause":cause(raw),"nano_status":nano_status(raw),"last_tx":tx,"ecu_rejected":false});
    if let Some(rest) = raw
        .split_once("command guard blocked before transport:")
        .or_else(|| raw.split_once("command guard blocked before USB:"))
        .map(|(_, rest)| rest)
    {
        let message = if rest.contains("profile=Seeds;") {
            "Security-data collection cannot submit an authorization key or perform module changes. OpenSAAB blocked this request before transport; this is a local policy refusal, not an ECU rejection.\n\nFinish collection through the original Security Access menu, then process the data and choose Resume in Full session. Do not retry Add automatically: earlier commands in a procedure may already have changed the vehicle."
        } else if rest.contains("controller=2 CAN_ID=241 service=AE profile=Read;") {
            "The ignition-key test requires Full native control. This session was read-only, so OpenSAAB stopped before sending the request. The ECU did not reject it.\n\nConnect and start opens a Full session. Follow the original firmware prompts for Check Ignition Key Status. The previous session and its logs have been saved."
        } else if (rest.contains(" service=27 ") || rest.contains("request=security_seed "))
            && rest.contains(" profile=Read;")
        {
            "Security seed collection was requested in a read-diagnostics session. OpenSAAB stopped before sending that request; the ECU did not reject it.\n\nChoose Get security access to start collection, then use the original Security Access menu. Seed collection does not process security data or submit an authorization key."
        } else {
            "The original software requested a command outside this session's supported operations. OpenSAAB stopped before sending it; this is not an ECU rejection. See Console for the command and session profile."
        };
        return out(
            "command_blocked",
            "Unsupported command for this session",
            message.into(),
        );
    }
    if disconnected(raw) {
        return out("adapter_disconnected", "Adapter disconnected",
            "The adapter stopped responding or was disconnected during the session. Reconnect the adapter, then choose Connect and start for a fresh VIN. No vehicle result from this session should be relied on.".into());
    }
    if let (Some(detail), Some(t)) = (transport_detail(raw), last_tx) {
        if t.is_single_wire_wake() {
            return out(
                "single_wire_wake_failed",
                "Single-wire CAN wake-up failed · Check pin 1",
                format!("{SW_WAKE_MESSAGE}\n\nAdapter detail: {detail}."),
            );
        }
        if raw.contains("ERR_CAN_WRITE_TIMEOUT") {
            return out("can_write_timeout", "CAN transmit not acknowledged",
                format!("The adapter could not transmit a frame on the {} CAN bus: no node acknowledged it in time. Check that the ECU is powered and the CAN wiring for that bus is connected. The original firmware stopped; no ECU reply was assumed.\n\nAdapter detail: {detail}.", t.bus));
        }
    }
    out("adapter_stopped", "Live adapter stopped",
        format!("The adapter reported an error and the session stopped. Diagnostic cause: {}. The operation did not complete; no ECU reply was assumed. Earlier commands may already have changed the vehicle. Preserve the report before retrying an Add/Remove procedure. See Console for the adapter detail.",cause(raw)))
}

/// Prefer driver-correlated in-flight evidence when a backend supplies it.
/// Existing drivers preserve their prior submitted-intent fallback.
pub fn classify_with_backend(
    raw: &str,
    submitted: Option<&TxContext>,
    active: Option<&crate::can_adapter::FailureContext>,
) -> Value {
    let mut out = classify(raw, active.map(|c| &c.tx).or(submitted));
    if let Some(c) = active {
        out["in_flight"] = json!({"controller":c.tx.controller,"ticket":c.ticket,
            "bus":c.tx.bus,"id":format!("{:03X}",c.tx.id),"dlc":c.tx.dlc,
            "wake":c.tx.wake,"phase":c.phase,"source":"adapter-worker"});
        out["last_tx_source"] = json!("adapter-worker");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wake() -> TxContext {
        TxContext {
            controller: 2,
            bus: "SingleWire",
            wake: true,
            id: 0x100,
            dlc: 0,
        }
    }
    const CHIPSOFT_001D: &str = "Chipsoft opcode=000F status=001D";
    const J2534_TIMEOUT: &str = "Native J2534 ERROR WRITE failed 00000009 last_error_rc=00000000 detail=ERR_CAN_WRITE_TIMEOUT";

    #[test]
    fn single_wire_wake_on_both_transports() {
        for raw in [CHIPSOFT_001D, J2534_TIMEOUT] {
            let v = classify(raw, Some(&wake()));
            assert_eq!(v["kind"], "single_wire_wake_failed", "{raw}");
            assert!(v["message"].as_str().unwrap().contains("pin 1"));
            assert_eq!(v["ecu_rejected"], false);
            assert_eq!(v["last_tx"]["bus"], "SingleWire");
        }
    }

    #[test]
    fn same_error_without_matching_wake_is_not_a_wake_failure() {
        // Ported from the Mac shell's negative cases: no TX, HS bus, other status, other frame.
        let hs = TxContext {
            bus: "HighSpeed",
            controller: 0,
            wake: false,
            id: 0x7e0,
            dlc: 8,
        };
        let not_wake = TxContext {
            wake: false,
            ..wake()
        };
        let other_frame = TxContext {
            id: 0x241,
            dlc: 8,
            ..wake()
        };
        assert_eq!(classify(CHIPSOFT_001D, None)["kind"], "adapter_stopped");
        assert_eq!(
            classify(CHIPSOFT_001D, Some(&hs))["kind"],
            "adapter_stopped"
        );
        assert_eq!(
            classify("Chipsoft opcode=000F status=0001", Some(&wake()))["kind"],
            "adapter_stopped"
        );
        assert_eq!(
            classify(CHIPSOFT_001D, Some(&not_wake))["kind"],
            "adapter_stopped"
        );
        assert_eq!(
            classify(CHIPSOFT_001D, Some(&other_frame))["kind"],
            "adapter_stopped"
        );
        let v = classify(J2534_TIMEOUT, Some(&hs));
        assert_eq!(v["kind"], "can_write_timeout");
        assert!(v["message"].as_str().unwrap().contains("HighSpeed"));
    }

    #[test]
    fn command_guard_messages_match_mac_shell() {
        let seeds = "Chipsoft command guard blocked before USB: controller=2 CAN_ID=257 service=27 profile=Read; no ECU rejection";
        let v = classify(seeds, Some(&wake()));
        assert_eq!(v["kind"], "command_blocked");
        assert!(v["message"]
            .as_str()
            .unwrap()
            .contains("Get security access"));
        let already = classify(&seeds.replace("profile=Read", "profile=Seeds"), None);
        assert!(!already["message"]
            .as_str()
            .unwrap()
            .contains("Get security access"));
        let ignition = "Chipsoft command guard blocked before USB: controller=2 CAN_ID=241 service=AE profile=Read; no ECU rejection";
        assert!(classify(ignition, None)["message"]
            .as_str()
            .unwrap()
            .contains("ignition-key test requires Full native control"));
        assert_ne!(classify(CHIPSOFT_001D, None)["kind"], "command_blocked");
    }

    #[test]
    fn mdi_policy_denial_is_distinct_from_transport_failure() {
        let ignition = "MDI command guard blocked before transport: controller=2 CAN_ID=241 service=AE profile=Read; no ECU rejection";
        let failure = classify(ignition, None);
        assert_eq!(failure["kind"], "command_blocked");
        assert!(failure["message"]
            .as_str()
            .unwrap()
            .contains("ignition-key test requires Full native control"));
        assert_eq!(failure["ecu_rejected"], false);
        assert_eq!(
            classify("MDI USB IN: IOKit 0xE00002C0", None)["kind"],
            "adapter_stopped"
        );
        assert_eq!(
            classify("MDI TCP device disconnected", None)["kind"],
            "adapter_disconnected"
        );
    }

    #[test]
    fn disconnect_and_unknown_are_explicit_and_bounded() {
        assert_eq!(
            classify("Chipsoft read: No such device (os error 6)", Some(&wake()))["kind"],
            "adapter_disconnected"
        );
        assert_eq!(
            classify("J2534 ERR_DEVICE_NOT_CONNECTED", None)["kind"],
            "adapter_disconnected"
        );
        let long = "x".repeat(1000);
        let v = classify(&long, None);
        assert_eq!(v["kind"], "adapter_stopped");
        assert_eq!(v["adapter_error"].as_str().unwrap().len(), 300);
        assert!(v["last_tx"].is_null());
    }
}

#[cfg(test)]
mod incident_tests {
    use super::*;
    #[test]
    fn nano_seed_guard_and_transport_faults_remain_distinct() {
        let refusal="VCX Nano command guard blocked before transport: controller=0 request=security_key profile=Seeds; no ECU rejection";
        let f = classify(refusal, None);
        assert_eq!(f["kind"], "command_blocked");
        assert_eq!(f["cause"], "local_policy_refusal");
        assert_eq!(f["ecu_rejected"], false);
        assert!(f["message"]
            .as_str()
            .unwrap()
            .contains("Resume in Full session"));
        for (raw, code) in [
            ("Nano checksum mismatch", "nano_checksum_mismatch"),
            ("Nano serial device disconnected", "adapter_disconnected"),
            (
                "Native Nano USB write deadline expired; outcome unknown",
                "transport_timeout",
            ),
            ("Nano opcode 48: status 96", "nano_adapter_status"),
            (
                "Native Nano USB write failed or was short; outcome unknown",
                "transport_write_failure",
            ),
        ] {
            assert_eq!(classify(raw, None)["cause"], code);
        }
        assert_eq!(
            classify("Nano opcode 48: status 96", None)["nano_status"],
            json!({"opcode":72,"status":150})
        );
        assert!(nano_status("opcode 48: status 96secret").is_none());
    }
    #[test]
    fn upload_summary_is_whitelisted_and_missing_progress_stays_unknown() {
        let mut f = classify("Nano checksum mismatch SECRET YS3FD49Y541000000", None);
        f["request_progress"] = json!({"last_request":"SECRET","potential_change_intents":"SECRET","requests_queued":2});
        let safe = support_summary(&f).unwrap();
        assert!(!safe.contains("SECRET") && !safe.contains("YS3"));
        assert!(
            safe.contains("potential_change_intents=unknown") && safe.contains("requests_queued=2")
        );
        f["cause"] = json!("SECRET");
        assert!(support_summary(&f).is_none());
    }
}
