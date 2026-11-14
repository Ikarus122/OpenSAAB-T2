// SPDX-License-Identifier: MPL-2.0
//! Private owned vLinker MC+ (MIC3313, ELM327-compatible) native RFCOMM backend,
//! HS-CAN (500 kbit/s, OBD pins 6/14) development preview for original-firmware reads.
//! Original CANdi owns all requests, padding, segmentation and flow control.
//!
//! Scope limits, stated rather than hidden:
//! - Controller 0 (HS-CAN / Saab P-bus) only. Single-wire CAN (controller 2, I-bus) and
//!   its high-voltage wake are rejected: no `VT` equivalent of `STPBRR 33333`/`STCSWM2`
//!   has been qualified on a MIC3313.
//! - Plain ELM commands are used (`ATSH`, raw data, `ATMA`); the MIC takes longer than an
//!   STN to switch headers, which the original CANdi tolerates as a late/missing reply.
//! - Completion is a Bluetooth write indication, never evidence of an electrical CAN ACK.
use crate::{
    adapters::{
        common::{
            policy::{CommandGate, KeyStatusGate, Profile},
            usb::SocketUsb,
        },
        stn_parser::{frame, Item, Parser},
    },
    can_adapter::{
        electrical_route, Backend, CompletionSource, ElectricalMode, Event, FailureContext,
    },
    candi_cpu::CanTransmission,
};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Write},
    net::TcpStream,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Local byte-bridge port; the MX+ bridge owns 35676.
pub const BRIDGE_PORT: u16 = 35677;
pub const READY: &str = "READY vlinker-native-read";
const MONITOR: &str = "ATMA";
/// ELM configuration after identity and voltage checks. No `ST` command is ever sent.
const SETUP: [&str; 14] = [
    "ATL0", "ATS1", "ATH1", "ATD1", "ATV1", "ATAL", "ATCAF0", "ATCFC0", "ATR0", "ATAT0", "ATST0A",
    "ATSP6", "ATCM000", "ATCF000",
];

/// Raw HS-CAN data bytes for an ELM `ATSH`-addressed transmission.
fn encode(controller: usize, tx: &CanTransmission) -> Result<String, String> {
    let route = electrical_route(controller, tx)?;
    if controller != 0 || route.mode != ElectricalMode::Data {
        return Err("vLinker HS-CAN preview: single-wire CAN and wake are not implemented".into());
    }
    if tx.frame.dlc == 0 {
        return Err("ELM raw mode cannot send a zero-DLC frame".into());
    }
    // ATCAF0 + ATV1: bytes go out exactly as given, without PCI or padding.
    Ok(tx.frame.data.iter().map(|b| format!("{b:02X}")).collect())
}
struct Link {
    socket: SocketUsb,
    parser: Parser,
    trace: File,
    started: Instant,
    receiving: bool,
    synchronized: bool,
    configured: bool,
    monitoring: bool,
    firmware: String,
    active_tx: Option<FailureContext>,
}
impl Link {
    fn open(token: &str, directory: &Path) -> Result<Self, String> {
        let socket = TcpStream::connect_timeout(
            &format!("127.0.0.1:{BRIDGE_PORT}").parse().unwrap(),
            Duration::from_secs(2),
        )
        .map_err(|e| e.to_string())?;
        Self::from_socket(token, directory, socket)
    }
    fn from_socket(token: &str, directory: &Path, socket: TcpStream) -> Result<Self, String> {
        socket.set_nodelay(true).map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|e| e.to_string())?;
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| e.to_string())?;
        let mut socket = SocketUsb(BufReader::new(socket));
        if socket.command(&format!("HELLO {token}"))? != READY {
            return Err("Native vLinker ownership unavailable".into());
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let trace = options
            .open(directory.join("vlinker-native-transcript-private.jsonl"))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            socket,
            parser: Parser::default(),
            trace,
            started: Instant::now(),
            receiving: false,
            synchronized: true,
            configured: false,
            monitoring: false,
            firmware: String::new(),
            active_tx: None,
        })
    }
    fn record(&mut self, event: serde_json::Value) -> Result<(), String> {
        writeln!(
            self.trace,
            "{}",
            serde_json::json!({"elapsed_ms":self.started.elapsed().as_millis(),"event":event})
        )
        .map_err(|e| e.to_string())
    }
    fn socket(&mut self, cmd: &str) -> Result<String, String> {
        if !self.synchronized {
            return Err(
                "ELM ordered transport uncertain; no replay or further in-band writes".into(),
            );
        }
        let result = self.socket.command(cmd);
        if result.is_err() {
            self.synchronized = false;
        }
        result
    }
    fn send(&mut self, cmd: &str) -> Result<(), String> {
        if self.receiving {
            return Err("ELM command refused while another exchange is active".into());
        }
        self.record(serde_json::json!({"tx_ascii":cmd}))?;
        if self.socket(&format!("WRITE {cmd}"))? != "WRITTEN" {
            return Err("Native RFCOMM write failed".into());
        }
        self.receiving = true;
        self.monitoring = cmd == MONITOR;
        Ok(())
    }
    fn packet(&mut self) -> Result<Vec<Item>, String> {
        let reply = self.socket("READ")?;
        if reply == "EMPTY" {
            return Ok(vec![]);
        }
        let value: serde_json::Value =
            serde_json::from_str(&reply).map_err(|_| "Invalid ELM byte packet")?;
        if value["type"] != "rx" {
            return Err("Unexpected ELM byte event".into());
        }
        let values = value["bytes"].as_array().ok_or("Missing ELM bytes")?;
        if values.len() > 1024 {
            return Err("ELM byte fragment too large".into());
        }
        let bytes = values
            .iter()
            .map(|v| {
                v.as_u64()
                    .filter(|v| *v <= 255)
                    .map(|v| v as u8)
                    .ok_or("Invalid ELM byte".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.record(serde_json::json!({"rx_ascii":String::from_utf8_lossy(&bytes)}))?;
        let items = self.parser.feed(&bytes)?;
        if items.iter().any(|v| matches!(v, Item::Prompt)) {
            self.receiving = false;
            if self.monitoring {
                self.monitoring = false;
                self.record(serde_json::json!({"monitor_exit":true}))?;
            }
        }
        Ok(items)
    }
    fn reply(&mut self, cmd: &str) -> Result<Vec<String>, String> {
        if self.receiving {
            return Err("ELM setup requires an idle prompt".into());
        }
        self.send(cmd)?;
        let end = Instant::now() + Duration::from_secs(3);
        let mut lines = vec![];
        while self.receiving {
            if Instant::now() > end {
                return Err(format!("ELM command prompt timeout: {cmd}"));
            }
            for item in self.packet()? {
                if let Item::Line(s) = item {
                    if s.trim() != cmd {
                        lines.push(s);
                    }
                }
            }
        }
        Ok(lines)
    }
    fn exact(&mut self, cmd: &str, expected: &str) -> Result<(), String> {
        let lines = self.reply(cmd)?;
        if lines
            .iter()
            .map(|s| s.split_whitespace().collect::<String>())
            .collect::<Vec<_>>()
            != [expected.split_whitespace().collect::<String>()]
        {
            return Err(format!("ELM readback rejected {cmd}: {lines:?}"));
        }
        Ok(())
    }
    fn setup(&mut self) -> Result<(), String> {
        // A sleeping adapter may publish a reset banner when RFCOMM opens.
        let end = Instant::now() + Duration::from_secs(2);
        let mut quiet = Instant::now();
        while quiet.elapsed() < Duration::from_millis(300) {
            if Instant::now() > end {
                return Err("ELM startup bytes did not settle".into());
            }
            if !self.packet()?.is_empty() {
                quiet = Instant::now();
                self.record(serde_json::json!({"startup_banner_drained":true}))?;
            }
        }
        self.parser = Parser::default();
        self.receiving = false;
        let reset = self.reply("ATZ")?;
        if reset.len() != 1 || !reset[0].trim().starts_with("ELM327") {
            return Err(format!("ELM reset rejected: {reset:?}"));
        }
        self.exact("ATE0", "OK")?;
        // MIC3313 identity: the vLinker MC+ answers VTVERS; an STN or generic clone does not.
        let version = self.reply("VTVERS")?;
        if version.len() != 1 || !version[0].trim().starts_with("MIC3313") {
            return Err(format!(
                "vLinker identity rejected (expected MIC3313): {version:?}"
            ));
        }
        self.firmware = version[0].trim().to_owned();
        let volts = self.reply("ATRV")?;
        let voltage = if volts.len() == 1 {
            volts[0]
                .trim()
                .strip_suffix('V')
                .and_then(|s| s.trim().parse::<f64>().ok())
        } else {
            None
        };
        if !voltage.is_some_and(|v| v.is_finite() && (11.5..=15.5).contains(&v)) {
            return Err(format!(
                "Bench adapter voltage unavailable or outside 11.5–15.5 V: {volts:?}"
            ));
        }
        self.record(serde_json::json!({"adapter_firmware":self.firmware,"adapter_voltage":voltage,"source":"ATRV"}))?;
        for cmd in SETUP {
            self.exact(cmd, "OK")?;
        }
        self.configured = true;
        self.record(serde_json::json!({"setup_complete":true,"bus":"HS-CAN only","bitrate":500000,"raw_frames":true,"receive_filter":"all 11-bit","host_flow_control":false,"host_ISOTP_assembly":false,"sw_can":false}))
    }
    fn receive(&mut self, events: &SyncSender<Event>) -> Result<(), String> {
        let monitoring = self.monitoring;
        for item in self.packet()? {
            if let Item::Line(line) = item {
                if let Some(f) = frame(&line)? {
                    self.record(
                        serde_json::json!({"received_frame":{"id":f.id,"dlc":f.dlc,"data":f.data}}),
                    )?;
                    events.try_send(Event::Received(0, f)).map_err(|_| {
                        "ELM receive queue full; session failed rather than discarding".to_string()
                    })?;
                } else if line.trim() == "STOPPED" && !monitoring {
                    return Err("ELM ordinary CAN request was unexpectedly interrupted".into());
                } else if !matches!(line.trim(), "" | "OK" | "STOPPED" | "NO DATA") {
                    // Includes CAN ERROR, BUFFER FULL, DATA ERROR, BUS BUSY: never silently dropped.
                    return Err(format!("ELM raw status: {line}"));
                }
            }
        }
        Ok(())
    }
    fn finish_request(&mut self, events: &SyncSender<Event>) -> Result<(), String> {
        if self.monitoring {
            return Err("Cannot finish indefinite monitoring as an ordinary request".into());
        }
        let end = Instant::now() + Duration::from_secs(3);
        while self.receiving {
            if Instant::now() > end {
                self.synchronized = false;
                return Err("ELM ordinary request prompt timeout; no interrupt or replay".into());
            }
            self.receive(events)?;
        }
        Ok(())
    }
    fn interrupt_monitor(
        &mut self,
        events: &SyncSender<Event>,
        reason: &str,
    ) -> Result<(), String> {
        if !self.receiving {
            return Ok(());
        }
        if !self.monitoring {
            return Err("Refused implicit interruption of an ordinary CAN request".into());
        }
        self.record(serde_json::json!({"monitor_interrupt":{"reason":reason,"controller":0},"ordinary_CAN_request_interrupted":false}))?;
        if self.socket("INTERRUPT")? != "WRITTEN" {
            return Err("ELM interrupt failed".into());
        }
        let end = Instant::now() + Duration::from_secs(2);
        while self.receiving {
            if Instant::now() > end {
                return Err("ELM prompt absent after interrupt".into());
            }
            self.receive(events)?;
        }
        Ok(())
    }
    fn cleanup(&mut self, events: &SyncSender<Event>) {
        let protocol = (|| -> Result<(), String> {
            if self.monitoring {
                self.interrupt_monitor(events, "session-close")?;
            } else {
                self.finish_request(events)?;
            }
            let counters = self.reply("ATCS")?;
            self.record(serde_json::json!({"CAN_status_before_close":counters}))?;
            if self.configured {
                self.exact("ATPC", "OK")?;
            }
            Ok(())
        })();
        // CLOSE is a local ownership command, permitted even after uncertain in-band I/O.
        let native = self.socket.command("CLOSE").and_then(|s| {
            if s == "CLOSED" {
                Ok(())
            } else {
                Err("Native Bluetooth close unconfirmed".into())
            }
        });
        let result = protocol.and(native);
        let _ = self.record(serde_json::json!({"cleanup":match result {Ok(())=>"confirmed".to_string(),Err(e)=>format!("unconfirmed: {e}")}}));
    }
}
#[derive(Clone, Debug)]
struct WorkerFailure {
    message: String,
    context: Option<FailureContext>,
}
pub struct Bridge {
    input: Option<SyncSender<(usize, CanTransmission)>>,
    output: Receiver<Event>,
    errors: Receiver<WorkerFailure>,
    failure: Option<FailureContext>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    gate: CommandGate,
    key_status: KeyStatusGate,
    confirmations: u64,
}
impl Bridge {
    pub fn start(token: &str, directory: &Path) -> Result<Self, String> {
        if token.len() != 32 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid vLinker owner token".into());
        }
        Ok(Self::from_link(Link::open(token, directory)?))
    }
    fn from_link(mut link: Link) -> Self {
        let (input, requests) = mpsc::sync_channel::<(usize, CanTransmission)>(32);
        let (events, output) = mpsc::sync_channel(4096);
        let (error, errors) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let cancelled = stop.clone();
        let worker = thread::spawn(move || {
            let result = (|| -> Result<(), String> {
                link.setup()?;
                while !cancelled.load(Ordering::Relaxed) {
                    if link.started.elapsed() > Duration::from_secs(1800) {
                        return Err(
                            "Private vLinker read session reached its 30-minute limit".into()
                        );
                    }
                    if let Ok((controller, tx)) = requests.try_recv() {
                        link.interrupt_monitor(&events, "next-guest-request")?;
                        link.active_tx = Some(FailureContext {
                            tx: crate::adapter_failure::TxContext::new(controller, &tx),
                            ticket: tx.ticket,
                            phase: "bus-setup",
                        });
                        let data = encode(controller, &tx)?;
                        // ELM reopens the protocol on the next transmission; the header is
                        // set explicitly every time because cached state cannot survive cancellation.
                        link.exact(&format!("ATSH{:03X}", tx.frame.id), "OK")?;
                        link.record(serde_json::json!({"guest_tx":{"controller":controller,"ticket":tx.ticket,"id":tx.frame.id,"dlc":tx.frame.dlc,"data":tx.frame.data}}))?;
                        link.active_tx.as_mut().unwrap().phase = "can-request";
                        link.send(&data)?;
                        link.finish_request(&events)?;
                        link.record(serde_json::json!({"ordinary_request_terminal_prompt":{"controller":controller,"ticket":tx.ticket},"responses_off":true,"original_CANdi_flow_control_owner":true,"electrical_ACK_verified":false}))?;
                        events
                            .try_send(Event::Completed {
                                controller,
                                ticket: tx.ticket,
                                source: CompletionSource::MicByteTransportWriteCompatibility,
                            })
                            .map_err(|_| "ELM event queue full".to_string())?;
                        link.active_tx = None;
                    } else if !link.receiving {
                        link.send(MONITOR)?;
                    } else {
                        link.receive(&events)?;
                    }
                }
                Ok(())
            })();
            if let Err(e) = result {
                let context = link.active_tx.clone();
                let _ = link.record(serde_json::json!({"failure":e,"in_flight":context.as_ref().map(|c|serde_json::json!({"controller":c.tx.controller,"ticket":c.ticket,"id":c.tx.id,"dlc":c.tx.dlc,"phase":c.phase}))}));
                let _ = error.send(WorkerFailure {
                    message: e,
                    context,
                });
            }
            link.cleanup(&events);
        });
        Self {
            input: Some(input),
            output,
            errors,
            failure: None,
            stop,
            worker: Some(worker),
            gate: CommandGate::default(),
            // The captured key-status DeviceControl lives on the I-bus, which this
            // preview does not reach; no DeviceControl is accepted here.
            key_status: KeyStatusGate {
                enabled: false,
                sent: 0,
            },
            confirmations: 0,
        }
    }
}
impl Backend for Bridge {
    fn poll(&mut self) -> Result<Vec<Event>, String> {
        if let Ok(e) = self.errors.try_recv() {
            self.failure = e.context;
            return Err(e.message);
        }
        let events: Vec<_> = self.output.try_iter().collect();
        self.confirmations += events
            .iter()
            .filter(|e| matches!(e, Event::Completed { .. }))
            .count() as u64;
        Ok(events)
    }
    fn transmit(&mut self, controller: usize, tx: CanTransmission) -> Result<(), String> {
        encode(controller, &tx)?;
        if !self
            .gate
            .allowed(controller, &tx, Profile::Read, Instant::now())
            && !self.key_status.allowed(controller, &tx)
        {
            return Err("vLinker original-firmware read policy rejected request".into());
        }
        self.input
            .as_ref()
            .ok_or("vLinker bridge closed")?
            .try_send((controller, tx))
            .map_err(|_| "vLinker transmit queue full/closed".into())
    }
    fn confirmations(&self) -> u64 {
        self.confirmations
    }
    fn failure_context(&self) -> Option<FailureContext> {
        self.failure.clone()
    }
    fn close(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.input = None;
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candi_cpu::{CanElectricalState, CanFrame};
    #[test]
    fn encodes_exact_hs_can_bytes_and_rejects_sw_can_and_empty_frames() {
        let mut tx = CanTransmission {
            frame: CanFrame {
                id: 0x240,
                extended: false,
                rtr: false,
                dlc: 8,
                data: vec![0x40, 0xa1, 2, 0x1a, 0x90, 0, 0, 0],
            },
            ticket: 1,
            btr0: 0xc1,
            btr1: 0x36,
            electrical: CanElectricalState::StandardCan,
        };
        assert_eq!(encode(0, &tx).unwrap(), "40A1021A90000000");
        assert!(encode(2, &tx).is_err());
        tx.frame.dlc = 3;
        tx.frame.data = vec![0x30, 0, 0];
        assert_eq!(encode(0, &tx).unwrap(), "300000");
        tx.frame.dlc = 0;
        tx.frame.data.clear();
        assert!(encode(0, &tx).is_err());
        // The SW-CAN wake route is valid for the MX+ but explicitly unsupported here.
        tx.frame.id = 0x100;
        tx.btr0 = 0xdd;
        tx.electrical = CanElectricalState::SingleWireGpio {
            latch: 2,
            assignment: 0,
            direction: 3,
        };
        assert!(encode(2, &tx).unwrap_err().contains("not implemented"));
    }
    #[test]
    fn trionic7_read_policy_admits_captured_reads_and_rejects_writes() {
        use crate::adapters::common::policy::{allowed_for_profile, trionic7_read};
        let t7 = |id: u32, data: Vec<u8>| CanTransmission {
            frame: CanFrame {
                id,
                extended: false,
                rtr: false,
                dlc: 8,
                data,
            },
            ticket: 1,
            btr0: 0xc1,
            btr1: 0x36,
            electrical: CanElectricalState::StandardCan,
        };
        // Captured 2006 9-5 T7 session: open, identifier read, reply-line acknowledgements.
        for (id, data) in [
            (0x220, vec![0x3f, 0x81, 0, 0x11, 2, 0x40, 0, 0]),
            (0x240, vec![0x40, 0xa1, 2, 0x1a, 0x97, 0, 0, 0]),
            (0x240, vec![0x40, 0xa1, 2, 0x21, 0x01, 0, 0, 0]),
            (0x240, vec![0x40, 0xa1, 4, 0x18, 0, 0xff, 0, 0]),
            (0x240, vec![0x40, 0xa1, 1, 0x3e, 0, 0, 0, 0]),
            (0x240, vec![0x40, 0xa1, 1, 0x82, 0, 0, 0, 0]),
            (0x266, vec![0x40, 0xa1, 0x3f, 0x85, 0, 0, 0, 0]),
            (0x266, vec![0x40, 0xa1, 0x3f, 0x80, 0, 0, 0, 0]),
        ] {
            assert!(trionic7_read(id, &data), "{id:#x} {data:02X?}");
            assert!(allowed_for_profile(0, &t7(id, data.clone()), Profile::Read));
            assert!(!allowed_for_profile(0, &t7(id, data), Profile::Seeds));
        }
        // Writes, clears, routines, security, downloads and programming sessions stay out.
        for data in [
            vec![0x40, 0xa1, 3, 0x3b, 0x90, 0x41, 0, 0],
            vec![0x40, 0xa1, 1, 0x14, 0, 0, 0, 0],
            vec![0x40, 0xa1, 2, 0x27, 0x05, 0, 0, 0],
            vec![0x40, 0xa1, 2, 0x31, 0x01, 0, 0, 0],
            vec![0x40, 0xa1, 4, 0x34, 0, 0, 0, 0],
            vec![0x40, 0xa1, 2, 0x10, 0x85, 0, 0, 0],
            vec![0x40, 0xa1, 2, 0x1a, 0x97, 1, 0, 0],
            vec![0x41, 0xa1, 2, 0x1a, 0x97, 0, 0, 0],
            vec![0x40, 0xa2, 2, 0x1a, 0x97, 0, 0, 0],
        ] {
            assert!(!trionic7_read(0x240, &data), "{data:02X?}");
            assert!(!allowed_for_profile(0, &t7(0x240, data), Profile::Read));
        }
        assert!(!trionic7_read(0x266, &[0x40, 0xa1, 0x3f, 0xc5, 0, 0, 0, 0]));
        assert!(!trionic7_read(0x258, &[0x40, 0xa1, 2, 0x1a, 0x97, 0, 0, 0]));
        assert!(!trionic7_read(0x220, &[0x3f, 0x81, 0, 0x11, 2, 0x40, 0]));
        // The I-bus controller never admits T7 frames.
        let mut sw = t7(0x240, vec![0x40, 0xa1, 2, 0x1a, 0x97, 0, 0, 0]);
        sw.btr0 = 0xdd;
        sw.electrical = CanElectricalState::SingleWireGpio {
            latch: 3,
            assignment: 0,
            direction: 3,
        };
        assert!(!allowed_for_profile(2, &sw, Profile::Read));
    }
    #[test]
    fn setup_sends_no_stn_commands() {
        assert!(SETUP.iter().all(|c| c.starts_with("AT")));
        assert!(SETUP.contains(&"ATSP6") && SETUP.contains(&"ATCAF0") && SETUP.contains(&"ATR0"));
        assert!(SETUP.contains(&"ATCM000") && SETUP.contains(&"ATCF000"));
    }
}

#[cfg(test)]
#[path = "vlinker_guest_tests.rs"]
mod byte_peer_tests;
