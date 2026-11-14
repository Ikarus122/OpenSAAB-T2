// SPDX-License-Identifier: MPL-2.0
//! Owned loopback byte peer with ELM/MIC3313 semantics. No Bluetooth, vehicle, or ECU firmware is opened.
use super::*;
use std::io::BufRead;
use std::net::TcpListener;
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

static PEERS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
enum Mode {
    Success,
    CanError,
    BufferFull,
    Stopped,
    MissingPrompt,
    StnIdentity,
    LowVoltage,
}

const REQUEST: &str = "40A1021A97000000";
const REQUEST_SW: &str = "021A900000000000";

struct Peer {
    directory: std::path::PathBuf,
    commands: Arc<Mutex<Vec<String>>>,
    thread: Option<JoinHandle<()>>,
}
impl Peer {
    fn open(mode: Mode) -> (Self, Link) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let directory = std::env::temp_dir().join(format!(
            "opensaab-vlinker-peer-{}-{}-{}",
            std::process::id(),
            PEERS.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let commands = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = commands.clone();
        let worker = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(socket);
            let mut replies = std::collections::VecDeque::<Vec<u8>>::new();
            let mut ordinary = false;
            let mut monitor = false;
            let mut ordinary_reads = 0;
            let mut requests = 0;
            let mut single_wire = false;
            loop {
                let mut line = String::new();
                let Ok(n) = reader.read_line(&mut line) else {
                    break;
                };
                if n == 0 {
                    break;
                }
                let command = line.trim_end().to_string();
                log.lock().unwrap().push(command.clone());
                let response = if command.starts_with("HELLO ") {
                    READY.to_string()
                } else if let Some(c) = command.strip_prefix("WRITE ") {
                    assert!(!ordinary, "A new write raced an ordinary request");
                    // Only the STN configuration a vLinker MC+ answered on the car; never STPX.
                    assert!(
                        !c.starts_with("ST")
                            || [
                                "STPC",
                                "STP61",
                                "STPR",
                                "STPBRR",
                                "STCSWM3",
                                "STFAC",
                                "STFPA000,000",
                                "STM"
                            ]
                            .contains(&c),
                        "Unqualified STN command sent to a MIC3313: {c}"
                    );
                    if c == "STP61" {
                        single_wire = true;
                    } else if c == "ATSP6" {
                        single_wire = false;
                    }
                    if c == "ATMA" || c == "STM" {
                        monitor = true;
                        if c == "STM" {
                            // Captured on a 2006 9-5 single-wire I-bus.
                            replies.push_back(b"100 RTR\r".to_vec());
                        }
                    } else if c == REQUEST || c == REQUEST_SW {
                        ordinary = true;
                        ordinary_reads = 0;
                        requests += 1;
                    } else {
                        let value = match c {
                            "ATZ" => "ELM327 v2.2",
                            "VTVERS" => {
                                if matches!(mode, Mode::StnIdentity) {
                                    "?"
                                } else {
                                    "MIC3313 V2.0.92"
                                }
                            }
                            "ATRV" => {
                                if matches!(mode, Mode::LowVoltage) {
                                    "11.2V"
                                } else {
                                    "12.6V"
                                }
                            }
                            "ATCS" => "T:00 R:00 F:00",
                            "STPR" => "61",
                            "STPBRR" => "33333",
                            _ => "OK",
                        };
                        replies.push_back(format!("{value}\r\r>").into_bytes());
                    }
                    "WRITTEN".to_string()
                } else if command == "READ" {
                    thread::sleep(Duration::from_millis(2));
                    if let Some(bytes) = replies.pop_front() {
                        serde_json::json!({"type":"rx","bytes":bytes}).to_string()
                    } else if ordinary {
                        ordinary_reads += 1;
                        // ATR1: the reply (captured on a 2006 9-5 T7) arrives fragmented
                        // before the prompt that ends the ordinary request.
                        let bytes = if requests == 1 || matches!(mode, Mode::Success) {
                            match mode {
                                Mode::MissingPrompt => Vec::new(),
                                Mode::CanError => b"CAN ERROR\r\r>".to_vec(),
                                Mode::BufferFull => b"BUFFER FULL\r\r>".to_vec(),
                                Mode::Stopped => b"STOPPED\r\r>".to_vec(),
                                _ if single_wire => b"541 8 06 5A 90 59 53 33 45 00\r\r>".to_vec(),
                                _ => match ordinary_reads {
                                    1 => b"258 8 C5 BF 20 5A 97".to_vec(),
                                    _ => b" 39 2D 35\r\r>".to_vec(),
                                },
                            }
                        } else {
                            b"\r>".to_vec()
                        };
                        if bytes.contains(&b'>') {
                            ordinary = false;
                        }
                        if bytes.is_empty() {
                            "EMPTY".to_string()
                        } else {
                            serde_json::json!({"type":"rx","bytes":bytes}).to_string()
                        }
                    } else {
                        "EMPTY".to_string()
                    }
                } else if command == "INTERRUPT" {
                    if ordinary {
                        ordinary = false;
                        replies.push_back(b"CAN ERROR\r\r>".to_vec());
                    } else {
                        assert!(monitor, "Unexpected interrupt outside monitoring");
                        monitor = false;
                        replies.push_back(b"STOPPED\r\r>".to_vec());
                    }
                    "WRITTEN".to_string()
                } else if command == "CLOSE" {
                    writeln!(reader.get_mut(), "CLOSED").unwrap();
                    break;
                } else {
                    panic!("Unknown byte operation {command}")
                };
                writeln!(reader.get_mut(), "{response}").unwrap();
            }
        });
        let socket = TcpStream::connect(address).unwrap();
        let link =
            Link::from_socket("00000000000000000000000000000000", &directory, socket).unwrap();
        (
            Self {
                directory,
                commands,
                thread: Some(worker),
            },
            link,
        )
    }
    fn close(mut self) -> Vec<String> {
        self.thread.take().unwrap().join().unwrap();
        let commands = self.commands.lock().unwrap().clone();
        std::fs::remove_dir_all(&self.directory).unwrap();
        commands
    }
}
fn tx(controller: usize, ticket: u64) -> CanTransmission {
    use crate::candi_cpu::{CanElectricalState, CanFrame};
    CanTransmission {
        ticket,
        btr0: if controller == 2 { 0xdd } else { 0xc1 },
        btr1: 0x36,
        electrical: if controller == 2 {
            CanElectricalState::SingleWireGpio {
                latch: 0x27,
                assignment: 0,
                direction: 0x7f,
            }
        } else {
            CanElectricalState::StandardCan
        },
        frame: CanFrame {
            id: 0x240,
            extended: false,
            rtr: false,
            dlc: 8,
            data: vec![0x40, 0xa1, 2, 0x1a, 0x97, 0, 0, 0],
        },
    }
}
fn run(backend: &mut dyn Backend, done: impl Fn(&[Event]) -> bool) -> (Vec<Event>, Option<String>) {
    let end = Instant::now() + Duration::from_secs(5);
    let mut events = vec![];
    while Instant::now() < end {
        match backend.poll() {
            Ok(v) => events.extend(v),
            Err(e) => return (events, Some(e)),
        }
        if done(&events) {
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }
    (events, None)
}

#[test]
fn hs_can_request_delivers_fragmented_t7_reply_before_completion() {
    let (peer, link) = Peer::open(Mode::Success);
    let mut backend =
        crate::can_adapter::TranslationBackend::new(Box::new(Bridge::from_link(link)));
    backend.transmit(0, tx(0, 42)).unwrap();
    let (events, error) = run(&mut backend, |e| {
        e.iter().any(|e| matches!(e, Event::Completed { .. }))
    });
    assert_eq!(error, None);
    // ATR1: the reply printed before the prompt is delivered first, then the completion.
    assert!(
        matches!(&events[0], Event::Received(0, f) if f.id == 0x258 && f.dlc == 8 && f.data == [0xc5, 0xbf, 0x20, 0x5a, 0x97, 0x39, 0x2d, 0x35])
    );
    assert!(matches!(
        events[1],
        Event::Completed {
            controller: 0,
            ticket: 42,
            ..
        }
    ));
    backend.close();
    let commands = peer.close();
    let setup: Vec<_> = commands
        .iter()
        .filter_map(|c| c.strip_prefix("WRITE "))
        .collect();
    assert_eq!(&setup[..4], ["ATZ", "ATE0", "VTVERS", "ATRV"]);
    assert!(setup.iter().all(|c| !c.starts_with("ST")));
    assert!(setup.contains(&"ATSP6") && setup.contains(&"ATCF218") && setup.contains(&"ATCM79F"));
    let sent = commands
        .iter()
        .position(|c| c == &format!("WRITE {REQUEST}"))
        .unwrap();
    assert_eq!(commands[sent - 2], "WRITE ATSH240");
    // Monitoring that was running before the request must have been interrupted first.
    if let Some(monitor) = commands[..sent].iter().rposition(|c| c == "WRITE ATMA") {
        assert!(commands[monitor..sent].iter().any(|c| c == "INTERRUPT"));
    }
    assert!(
        commands[sent..].iter().any(|c| c == "WRITE ATMA"),
        "receive returns to monitoring after the request"
    );
    assert_eq!(
        commands
            .iter()
            .filter(|c| *c == &format!("WRITE {REQUEST}"))
            .count(),
        1
    );
    assert!(commands.iter().any(|c| c == "WRITE ATPC"));
    assert_eq!(commands.last().unwrap(), "CLOSE");
}

fn sw_read(ticket: u64) -> CanTransmission {
    let mut t = tx(2, ticket);
    t.frame.id = 0x241;
    t.frame.data = vec![2, 0x1a, 0x90, 0, 0, 0, 0, 0];
    t
}

fn single_wire_read_then_back_to_hs_can() {
    let (peer, link) = Peer::open(Mode::Success);
    let mut backend =
        crate::can_adapter::TranslationBackend::new(Box::new(Bridge::from_link(link)));
    backend.transmit(2, sw_read(41)).unwrap();
    let (mut events, error) = run(&mut backend, |e| {
        e.iter().any(|e| matches!(e, Event::Completed { .. }))
    });
    assert_eq!(error, None);
    // Let single-wire monitoring run (and see its 0x100 RTR line) before the HS request.
    thread::sleep(Duration::from_millis(150));
    backend.transmit(0, tx(0, 42)).unwrap();
    let (more, error) = run(&mut backend, |e| {
        e.iter().any(|e| matches!(e, Event::Completed { .. }))
    });
    assert_eq!(error, None);
    events.extend(more);
    let order: Vec<_> = events
        .iter()
        .map(|e| match e {
            Event::Received(c, f) => format!("rx{c}:{:03X}", f.id),
            Event::Completed {
                controller, ticket, ..
            } => format!("done{controller}:{ticket}"),
        })
        .collect();
    assert_eq!(order, ["rx2:541", "done2:41", "rx0:258", "done0:42"]);
    assert!(
        matches!(&events[0], Event::Received(2, f) if f.data == [6, 0x5a, 0x90, 0x59, 0x53, 0x33, 0x45, 0])
    );
    backend.close();
    let commands = peer.close();
    let writes: Vec<_> = commands
        .iter()
        .filter_map(|c| c.strip_prefix("WRITE "))
        .collect();
    let sw = writes.iter().position(|c| *c == "STP61").unwrap();
    assert_eq!(
        &writes[sw - 1..sw + 8],
        [
            "STPC",
            "STP61",
            "STPR",
            "STPBRR",
            "STCSWM3",
            "STFAC",
            "STFPA000,000",
            "ATSH241",
            REQUEST_SW
        ]
    );
    let hs = writes.iter().position(|c| *c == REQUEST).unwrap();
    assert_eq!(
        &writes[hs - 5..hs],
        ["STPC", "ATSP6", "ATCF218", "ATCM79F", "ATSH240"]
    );
    // Single-wire monitoring ran, and its zero-length 0x100 line was not delivered.
    assert!(writes[sw..hs].contains(&"STM"));
    assert!(!writes
        .iter()
        .any(|c| c.starts_with("STPX") || *c == "STCSWM2"));
}
#[test]
fn single_wire_read_selects_33k_then_returns_to_hs_can_filter() {
    single_wire_read_then_back_to_hs_can();
}

#[test]
fn single_wire_wake_is_rejected_before_any_write() {
    let (peer, link) = Peer::open(Mode::Success);
    let mut backend = Bridge::from_link(link);
    let mut wake = tx(2, 40);
    wake.frame.id = 0x100;
    wake.frame.dlc = 0;
    wake.frame.data.clear();
    wake.electrical = crate::candi_cpu::CanElectricalState::SingleWireGpio {
        latch: 2,
        assignment: 0,
        direction: 3,
    };
    assert!(backend
        .transmit(2, wake)
        .unwrap_err()
        .contains("wake not implemented"));
    backend.close();
    let commands = peer.close();
    assert!(!commands
        .iter()
        .any(|c| c.starts_with("WRITE ATSH") || c.contains("STP61") || c.contains("STPX")));
}

fn failure_case(mode: Mode, expected: &str) {
    let (peer, link) = Peer::open(mode);
    let mut backend =
        crate::can_adapter::TranslationBackend::new(Box::new(Bridge::from_link(link)));
    backend.transmit(0, tx(0, 42)).unwrap();
    backend.transmit(0, tx(0, 43)).unwrap();
    let (events, error) = run(&mut backend, |_| false);
    assert!(error.as_deref().unwrap().contains(expected), "{error:?}");
    assert!(!events.iter().any(|e| matches!(e, Event::Completed { .. })));
    let actual = backend.failure_context().unwrap();
    assert_eq!(
        (actual.tx.controller, actual.ticket, actual.phase),
        (0, 42, "can-request")
    );
    backend.close();
    let commands = peer.close();
    assert_eq!(
        commands
            .iter()
            .filter(|c| *c == &format!("WRITE {REQUEST}"))
            .count(),
        1,
        "no replay"
    );
    let first = commands
        .iter()
        .position(|c| c == &format!("WRITE {REQUEST}"))
        .unwrap();
    assert!(!commands[first + 1..].iter().any(|c| c == "INTERRUPT"));
    assert_eq!(commands.iter().filter(|c| *c == "CLOSE").count(), 1);
}
#[test]
fn can_error_prevents_completion_and_the_queued_next_write() {
    failure_case(Mode::CanError, "CAN ERROR");
}
#[test]
fn buffer_full_is_a_failure_not_a_silent_drop() {
    failure_case(Mode::BufferFull, "BUFFER FULL");
}
#[test]
fn unexpected_stopped_is_not_a_successful_completion() {
    failure_case(Mode::Stopped, "unexpectedly interrupted");
}
#[test]
fn missing_prompt_closes_native_without_interrupt_or_replay() {
    failure_case(Mode::MissingPrompt, "prompt timeout");
}

fn setup_rejection(mode: Mode, expected: &str) {
    let (peer, link) = Peer::open(mode);
    let mut backend = Bridge::from_link(link);
    let (_, error) = run(&mut backend, |_| false);
    assert!(error.as_deref().unwrap().contains(expected), "{error:?}");
    backend.close();
    let commands = peer.close();
    assert!(
        !commands
            .iter()
            .any(|c| c.starts_with("WRITE ATSP") || c == "WRITE ATMA"),
        "{commands:?}"
    );
    assert_eq!(commands.last().unwrap(), "CLOSE");
}
#[test]
fn non_mic_identity_stops_before_bus_configuration() {
    setup_rejection(Mode::StnIdentity, "identity rejected");
}
#[test]
fn low_adapter_voltage_stops_before_bus_configuration() {
    setup_rejection(Mode::LowVoltage, "outside 11.5");
}
