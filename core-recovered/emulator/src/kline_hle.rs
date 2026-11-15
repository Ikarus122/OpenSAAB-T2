// SPDX-License-Identifier: MPL-2.0
//! Host K-line for the original firmware's KW2000 link (VCI protocol 0x1308).
//!
//! The firmware's transmit task (link slot argument, image 148.000) takes a request from
//! its `Xmt<n>` queue, builds the complete KWP frame in the request buffer, records it as
//! the link's current transmission and starts the UART/TPU timing at `$1D0C6A`. Here that
//! start is replaced: the frame goes to the vLinker, the reply frame is written to the
//! link's current receive descriptor (`+0` length, `+4` status, `+8` buffer) and the
//! firmware's own `$1D370E` posts it to `Rcv<n>` exactly as its interrupt path does.
//! Like the end-of-frame step of its timer handler (`$1D3C22`), the posted frame is
//! `[target, source, data...]`: format, length byte and checksum removed.
//! K-line is one wire, so the interface also reads back its own frame: with echo
//! filtering off (link `+$50` bit 15 clear, as the application configures it) the
//! firmware posts that echo first, and the application waits for it before the reply.
//! The echo is posted from the call site, the reply when the task resumes after it.
//! Nothing is invented: no reply means no message, and the guest times out as with a
//! silent module.
use crate::bus::Tech2Bus;
use m68k::{AddressBus, CpuCore};
use tech2_emu::adapters::vlinker_guest::KLINE_PROTOCOL_KW2000;

/// UART/TPU timing start for a link: `(link, word, word)`, returns with `rtd #8`.
const TIMING_START: u32 = 0x001D_0C6A;
/// Return address of the call in the KW2000 transmit task.
const TRANSMIT_TASK_RETURN: u32 = 0x001D_3664;
/// Posts the current receive descriptor of `(link)` to its `Rcv<n>` queue.
const POST_RECEIVED: u32 = 0x001D_370E;
const RX_BUFFER: usize = 0x104;
/// StartCommunication step of the fast-init state machine in `$1D2FA6(link, events)`,
/// reached after the wake-up pattern timing (by then the application has set the target
/// with `IR`); `$1D330A` is the loop exit that restores the link's `Rcv<n>` and posts one
/// result per responder from the frame's locals.
const INIT_START_COMMUNICATION: u32 = 0x001D_3148;
const INIT_FINISH: u32 = 0x001D_330A;
/// The state machine's event wait (`ev_receive`, no timeout) and its return. Without the
/// UART/TPU interrupts the wake-up timing events never come, so the wait is bounded and a
/// timeout reads as "no event": the machine then steps on as after its timer.
const INIT_WAIT_CALL: u32 = 0x001D_3066;
const INIT_WAIT_RETURN: u32 = 0x001D_306C;
const INIT_WAIT_TICKS: u32 = 5;

/// `[target, source, data...]` of a checked raw KWP frame, as `$1D3C22` stores it.
fn received_form(frame: &[u8]) -> Vec<u8> {
    let header = if frame[0] & 0x3F == 0 { 4 } else { 3 };
    let mut out = vec![frame[1], frame[2]];
    out.extend_from_slice(&frame[header..frame.len() - 1]);
    out
}

/// Writes a frame into the link's current receive descriptor and enters
/// `$1D370E(link)` (`rtd #4`) returning to `ret`; the call frame is pushed below `sp`.
fn post_frame(cpu: &mut CpuCore, bus: &mut Tech2Bus, link: u32, frame: &[u8], ret: u32, sp: u32) {
    let state = link + 0x52;
    let descriptor = bus.read_long(state + 6);
    let buffer = bus.read_long(descriptor + 8);
    let frame = received_form(frame);
    for (i, b) in frame.iter().enumerate() {
        bus.write_byte(buffer + i as u32, *b);
    }
    bus.write_word(descriptor, frame.len() as u16);
    bus.write_word(descriptor + 4, 0);
    bus.write_long(sp - 8, ret);
    bus.write_long(sp - 4, link);
    cpu.set_sp(sp - 8);
    cpu.pc = POST_RECEIVED;
}

fn kw2000_init_context(cpu: &CpuCore, bus: &mut Tech2Bus) -> bool {
    let link = cpu.dar[12];
    cpu.dar[13] == link.wrapping_add(0x52) && bus.read_word(link + 0x18) == KLINE_PROTOCOL_KW2000
}

/// Fast init through the adapter: StartCommunication to the link's target, then the
/// firmware's own exit path with the responder, service and key bytes it would have
/// collected (`$1D3222..$1D32BA`). No reply leaves the failure flag set, so the firmware
/// retries or reports as with a silent module.
fn fast_init(cpu: &mut CpuCore, bus: &mut Tech2Bus) {
    if !kw2000_init_context(cpu, bus) {
        return;
    }
    let link = cpu.dar[12];
    let state = cpu.dar[13];
    let target = bus.read_byte(state + 0x60);
    let source = bus.read_byte(state + 0xEE);
    let mut frame = vec![0x81, target, source, 0x81];
    frame.push(frame.iter().fold(0u8, |a, v| a.wrapping_add(*v)));
    let mut session = bus.kline.take().unwrap();
    let result = session.exchange(&frame);
    bus.kline = Some(session);
    let reply = match result {
        Ok(frames) => frames.into_iter().find(|f| f.len() >= 7 && f[f.len() - 4] == 0xC1),
        Err(e) => {
            bus.trace_event("kline_failure", &e);
            bus.failure_reason = Some(format!("vLinker K-line: {e}"));
            None
        }
    };
    let detail = format!("fast init link={link:#010x} tx={frame:02X?} rx={reply:02X?}");
    eprintln!("KLINE {detail}");
    bus.trace_event("kline_fast_init", &detail);
    let sp = cpu.sp();
    let responders = if let Some(r) = reply {
        let n = r.len();
        let (kb1, kb2) = (r[n - 3], r[n - 2]);
        let key = kb1 as u16 | (kb2 as u16) << 8;
        bus.write_word(sp + 0x6E, r[1] as u16);
        bus.write_word(sp + 0x46, r[2] as u16);
        bus.write_word(sp + 0x44, 0xC1);
        bus.write_word(sp + 0x1C, key);
        bus.write_word(state + 0x5A, key);
        if kb1 == 0xD0 {
            let (a, l) = (bus.read_word(state + 0xF4), bus.read_word(state + 0xF6));
            bus.write_word(state + 0xF0, a);
            bus.write_word(state + 0xF2, l);
        } else {
            bus.write_word(state + 0xF0, (kb1 & 8) as u16);
            bus.write_word(state + 0xF2, (kb1 & 2) as u16);
        }
        if bus.read_byte(state + 0x12E) == 0 {
            bus.write_byte(state + 0x12F, 1);
        }
        bus.write_word(sp + 0x70, 0);
        1
    } else {
        bus.write_word(sp + 0x70, 1);
        0
    };
    cpu.dar[5] = (cpu.dar[5] & 0xFFFF_0000) | responders;
    cpu.pc = INIT_FINISH;
}

pub fn before_instruction(cpu: &mut CpuCore, bus: &mut Tech2Bus) {
    if bus.kline.is_none() {
        return;
    }
    if cpu.pc == INIT_WAIT_CALL && kw2000_init_context(cpu, bus) {
        let timeout = cpu.sp() + 8;
        if bus.read_long(timeout) == 0 {
            bus.write_long(timeout, INIT_WAIT_TICKS);
        }
        return;
    }
    if cpu.pc == INIT_WAIT_RETURN && cpu.dar[0] != 0 && kw2000_init_context(cpu, bus) {
        bus.write_long(cpu.dar[14], 0);
        return;
    }
    if cpu.pc == INIT_START_COMMUNICATION {
        return fast_init(cpu, bus);
    }
    if cpu.pc == TRANSMIT_TASK_RETURN {
        if let Some((link, frame)) = bus.kline_reply.take() {
            let sp = cpu.sp();
            post_frame(cpu, bus, link, &frame, TRANSMIT_TASK_RETURN, sp);
        }
        return;
    }
    if cpu.pc != TIMING_START {
        return;
    }
    let sp = cpu.sp();
    if bus.read_long(sp) != TRANSMIT_TASK_RETURN {
        return;
    }
    let link = bus.read_long(sp + 4);
    if bus.read_word(link + 0x18) != KLINE_PROTOCOL_KW2000 {
        return;
    }
    let state = link + 0x52;
    let request = bus.read_long(state + 0x10);
    // The replaced call's return address and arguments leave the stack as its `rtd #8`.
    let (ret, caller_sp) = (bus.read_long(sp), sp + 12);
    if request == 0 {
        cpu.pc = ret;
        cpu.set_sp(caller_sp);
        return;
    }
    let len = (bus.read_word(request) as usize).min(RX_BUFFER);
    let data = bus.read_long(request + 8);
    let frame: Vec<u8> = (0..len as u32).map(|i| bus.read_byte(data + i)).collect();
    // The transmission is complete once the adapter has it; the task must not wait.
    bus.write_long(state + 0x10, 0);
    let mut session = bus.kline.take().unwrap();
    let result = session.exchange(&frame);
    bus.kline = Some(session);
    let reply = match result {
        Ok(frames) => frames.into_iter().last(),
        Err(e) => {
            bus.trace_event("kline_failure", &e);
            bus.failure_reason = Some(format!("vLinker K-line: {e}"));
            None
        }
    };
    let detail = format!("link={link:#010x} tx={frame:02X?} rx={reply:02X?}");
    eprintln!("KLINE {detail}");
    bus.trace_event("kline_exchange", &detail);
    bus.kline_reply = reply.filter(|r| r.len() <= RX_BUFFER).map(|r| (link, r));
    post_frame(cpu, bus, link, &frame, ret, caller_sp);
}
