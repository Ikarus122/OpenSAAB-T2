# ECM diagnostic preview 0.2.29-ecm-preview.1

This preview addresses observable workflow/reporting gaps found while reviewing
a T8 ECM Add report. It does not establish that the reported stop has been
reproduced or that T8 ECM Add/Remove is fixed or qualified.

Changes:

- Normal USB Connect and start uses the existing Full binding for Nano,
  Chipsoft and MDI regardless of a saved limited-mode preference. This follows
  Android's normal-full-session-1 rule (SessionModes at c2e38ff69979d404b22457de709381a6fb8eb017).
  Separate collection and maintenance/research entry points keep their scope.
  Mac MX+ retains its limited binding and receives no new capability claim.
- Nano frontend and worker policy refusals share the existing command-blocked
  classification. Collection cannot submit keys or service writes. The message
  explains collection, processing and explicit Full continuation separately.
- An already processed card in a collection/read session offers Resume in Full
  session rather than focusing the limited firmware session. Confirmed cleanup
  and the existing adapter identity checks remain required. Import success also
  names the resumed mode. No automatic vehicle request retry is introduced.
- Per-session support messages preserve fixed first-error cause labels,
  validated numeric Nano opcode/status and passive request intent/queue counts.
  They exclude raw errors, frames, VINs, seeds, keys and paths. Existing frozen
  review, consent and explicit sending remain. This uses the deployed message
  field rather than requiring a new server schema.

Evidence limits:

The prior exact Intel .5 run covered seed collection, processing/import and
readback; it never selected Add/Remove or submitted a key. Original firmware
control-flow research found potential VIN/pairing changes before a later ECM
security attempt. Offline helper execution is not wire/ECU/commit evidence.

The new observer counts recognized requests at the native adapter boundary.
Queue acceptance does not prove transmission, ECU acceptance or persistence.
Unknown/unrecognized commands and previous sessions prevent any zero-count
claim of an unchanged vehicle. No exact Add UI phase or durable-commit boundary
is inferred. A stop remains a reason to preserve evidence, not retry Add.

Handoff checks:

1. Install the exact versioned app alongside the retained version, with no
   active diagnostic session. Keep the existing application support directory.
2. Verify displayed full version/Intel identity. Use ECU information/readback
   first. Get security access remains a separate collection/processing flow;
   follow the original physical ignition prompts.
3. If a stop occurs, prepare and review Report issue, describe the last original
   menu/action, then explicitly send. Retain the OS receipt. POST-AUTH means
   processed local data, not current ECU authorization.
4. Further Add/Remove validation requires an isolated setup with verified
   restoration, including the other modules affected by the procedure. The
   initial handoff does not request an Add retry on an installed vehicle.

Build, signing, installed and physical receipts are retained outside source.
Intel macOS 13 compatibility, adapter workflows and complete Add/Remove remain
separate checks. Shared Rust/Swift source carries the change to Apple silicon;
iOS/other hosts need their own binding/build/installed/physical verification.
