# Terminal transport protocol v1

The terminal WebSocket uses binary messages only. Each WebSocket message contains exactly one frame. All integers are unsigned big-endian. The server rejects text messages, malformed lengths, unknown mandatory flags, payloads larger than 1 MiB, and protocol versions other than 1.

## Fixed 36-byte header

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | Magic bytes `CM` |
| 2 | 1 | Protocol version (`1`) |
| 3 | 1 | Frame kind |
| 4 | 2 | Flags |
| 6 | 2 | Header size (`36`) |
| 8 | 8 | Monotonic output sequence, acknowledgement target, input idempotency key, or `0` |
| 16 | 16 | Binary UUID terminal-tab ID; all zeroes only for connection-scoped ping/pong |
| 32 | 4 | Payload byte length |

The payload immediately follows the header.

## Frame kinds

| Value | Name | Direction | Payload |
| ---: | --- | --- | --- |
| 1 | output | server → client | Raw untrusted PTY bytes |
| 2 | input | client → server | Raw user input bytes; active lease required |
| 3 | ack | either | Empty; an output acknowledgement or application-level input receipt |
| 4 | resize | client → server | Four `uint16`: rows, columns, width pixels, height pixels |
| 5 | ping | either | Up to 64 opaque bytes echoed by pong |
| 6 | pong | either | Ping payload |
| 7 | replay-gap | server → client | UTF-8 reason; sequence is earliest retained output and is followed by the complete retained window |
| 8 | lease-request | client → server | UTF-8 device ID; flag `1` means explicit take-control |
| 9 | lease-granted | server → client | UTF-8 current device ID |
| 10 | lease-denied | server → client | UTF-8 current device ID |
| 11 | tab-closed | server → client | UTF-8 non-sensitive reason code |
| 12 | attention | server → client | UTF-8 generic event kind; no command/output detail |

## Flags, acknowledgements, and recovery

| Value | Name | Valid frame | Meaning |
| ---: | --- | --- | --- |
| `0x0001` | take-lease | lease-request | Explicitly displace the current input-lease holder |
| `0x0002` | idempotent-input | input | Sequence is a non-zero client-generated idempotency key; server writes the bytes at most once per device and tab replay generation |
| `0x0004` | input-receipt | ack | Server confirms that the idempotent input identified by sequence was written (or had already been written) |
| `0x0008` | input-receipt-confirmed | ack | Client confirms the application received `input-receipt` with the same sequence |

An input without `idempotent-input` has sequence `0` and retains best-effort interactive-key semantics. An input with `idempotent-input` must use a non-zero, unpredictable key that remains unchanged across retries. The server retains bounded active receipt sets per device and per tab for the replay generation, including a digest of the accepted bytes, and rejects reuse of a key with different input. Active records with lost receipts or confirmations are never evicted: if either active capacity is exhausted, a new idempotent input is rejected before any PTY write.

The server returns an empty `ack` with `input-receipt` and the same key only after the PTY write succeeds; retries receive the same receipt without another write. The receipt is delivered only to the originating WebSocket through its reliable, backpressured writer path; it is never broadcast to other devices or discarded by the lossy output-subscriber buffer. The record becomes confirmable only after the WebSocket write succeeds. After the application receives the receipt, it sends an empty `ack` with `input-receipt-confirmed` and the same sequence on that WebSocket. Confirmations are device-scoped, idempotent, and cannot delete another device's record. Confirmation releases active capacity and moves the digest into a larger bounded rolling tombstone set: matching late retries remain deduplicated and receive another receipt, while mismatched reuse is rejected. Tombstones may be evicted only after application confirmation, when a conforming client has no delivery left to retry.

Composer drafts and attachments are considered sent only after receiving the receipt and submitting its confirmation. A client-to-server output `ack` has flags `0` and sequence equal to the highest contiguous output processed. `input-receipt` and `input-receipt-confirmed` cannot be combined on one frame. Receipt state is scoped to the in-memory gateway replay generation; a control-plane crash after a PTY write can still make a cross-generation retry ambiguous. Likewise, app termination after confirmation but before the encrypted draft is cleared can leave a user-visible draft whose later resend needs an explicit duplicate warning or durable client key to be exactly-once.

Output sequences are scoped to a tab and increase monotonically within a gateway replay generation. Reconnect supplies the last acknowledged sequence as a query parameter. The server replays later retained output or emits `replay-gap`; it never silently pretends a truncated replay is complete. A cursor ahead of the current generation (for example, after a control-plane restart) also produces a gap whose sequence is the next coherent output sequence. On `replay-gap`, the client clears the tab renderer and cached terminal history, sets its expected sequence to one before the announced earliest sequence, and rebuilds from the complete retained frame window sent immediately after the gap marker. Live output continues after that window.

Reconnect tokens are rotating hints, not the owner credential. When a connection-descriptor request made with a reconnect token is rejected, the authenticated client clears that token and retries once without it instead of repeatedly presenting stale state.

Only one device may hold the input lease. Viewing, acknowledgement, and ping do not require the lease. Resize is accepted only from the current holder. Lease takeover is explicit and audited.

Remote clipboard commands (including OSC 52) are filtered before output frames reach the app. Hyperlinks remain untrusted and require native confirmation.
