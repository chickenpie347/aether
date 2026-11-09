# AETHER Suite

A research proof of concept for secure communication between AI agents, and between agents and the hosts
(robots, servers, runtimes) they act on. It combines a QUIC-based messaging protocol (AETHER) with a
decentralised trust and authority framework (the Mevrsic Trust Authority, MTA), and implements the core
mechanics end to end with post-quantum cryptography.

> **Status: research prototype. Not production software.** The cryptography is pure Python, unaudited, and
> includes a patched copy of a third-party TLS module. Do not use it to protect anything real. See
> [Limitations](#limitations).

## The idea in one paragraph

Agents will increasingly talk to each other and operate physical and digital systems. That needs three things
that existing agent protocols only partly cover: **verifiable identity**, **scoped and revocable authority**,
and **messages that say how sure the sender is**. AETHER Suite treats them as separate concerns, and rests on
one rule: **a message is a request, never authority.** Every request passes identity, trust, authorisation, and
then a host-local safety controller that no remote party can override.

## Architecture

```
+--------------------------------------------------------------+
| ASSURANCE PLANE   audit, legibility, halt, governance         |
+--------------------------------------------------------------+
| TRUST PLANE       DIDs, credentials, scoped issuer registry   |
| AUTHORITY LAYER   attenuating delegation, revocation, epochs  |
+--------------------------------------------------------------+
| COORDINATION      tasks, commitments, consensus               |
| SEMANTIC LAYER    typed envelopes, epistemic metadata         |
| SESSION LAYER     HELLO, PRESENT (channel-bound), DELEGATE    |
| TRANSPORT         QUIC v1 + hybrid post-quantum TLS 1.3       |
+--------------------------------------------------------------+
| ENFORCEMENT BOUNDARY  host-local, independent of all above    |
+--------------------------------------------------------------+
```

Design principles:

1. A message is not authority.
2. Identity, trust, authorisation and execution are verified separately.
3. Machine-native on the wire, human-auditable at rest. Every message type has a human-readable rendering.
4. Privacy on the wire, accountability at the endpoints.
5. Self-description is not evidence: advertised capabilities are never treated as granted authority.
6. Stale or missing trust reduces authority and never expands it.
7. Reuse proven standards. No new transport cryptography.

## Versions

The repository holds three successive versions of the proof of concept. Each is self-contained and runnable.
**Start with v3**; the earlier versions are kept as a record of how the design evolved.

| Version | Transport | Signatures | Checks | What it added |
|---|---|---|---|---|
| [`v1/`](v1/) | Encrypted TCP stand-in (X25519 + ChaCha20-Poly1305) | Ed25519 | 45 | The protocol core: trust plane, scoped issuers, attenuating delegation, signed envelopes, epistemic block, enforcement boundary, HALT, revocation, freshness policy, audit log |
| [`v2/`](v2/) | **Real QUIC v1** with hybrid **X25519 + ML-KEM-768** TLS 1.3 | Ed25519 | 54 | Real QUIC streams and datagrams, TLS-exporter channel binding, classical-only peers refused, man-in-the-middle detection, spin bit disabled |
| [`v3/`](v3/) | Same as v2 | **Hybrid Ed25519 + ML-DSA-65** | 66 | Post-quantum signatures on every identity, credential, delegation, envelope and receipt; session-authenticated datagrams |

Each version's own `README.md` has run instructions, validation notes and caveats.

## Quick start

```bash
cd v3
pip install -r requirements.txt
python3 demo.py                 # 66 checks, about 10 seconds, non-zero exit on any failure
python3 crosscheck_pq.py        # optional: checks ML-KEM and ML-DSA against liboqs (needs liboqs installed)
```

Requires Python 3.10 or later and IPv4 loopback. The demo starts a QUIC host and several agents in one
process and runs every scenario against it over real sockets.

## What the demo shows

Each check exercises one claim of the design against a live host:

- **Authority is not execution.** A fully authorised request for an unsafe action is refused by the host's local
  controller.
- **Delegation only narrows.** Broadening actions, loosening or dropping a limit, or delegating past the depth
  limit is rejected at every link of the chain.
- **Channel binding defeats relays.** A man-in-the-middle that terminates QUIC on both sides gets a different TLS
  exporter on each leg, and the agent detects it.
- **Post-quantum by construction.** A classical-only peer is refused in the handshake. With Ed25519 simulated as
  broken, a forged credential is still rejected because ML-DSA must also verify.
- **Fail safe.** Stale registry state restricts physical actions until refreshed. A suspended provider is cut off
  immediately and the host enters a safe state.
- **Honest claims.** Forwarding cannot upgrade a claim from "inferred" to "observed". Retractions cascade to
  dependent claims. Injected instructions inside inference data have no effect.
- **Accountability.** HALT requires its own credential. The audit log is hash-chained and tamper-evident, and
  every entry is human-readable.

## Repository layout

```
.
├── README.md            this file
├── v1/                  protocol core over an encrypted TCP stand-in
├── v2/                  QUIC + hybrid ML-KEM transport
├── v3/                  hybrid ML-DSA signatures (current)
└── docs/                specification and design notes (if included)
```

Inside `v2/` and `v3/`:

| File | Purpose |
|---|---|
| `aether_poc.py` | Transport-independent core: trust plane, delegation, envelopes, host pipeline, enforcement boundary, audit |
| `aether_quic.py` | QUIC server and client, streams, datagrams, test relay |
| `pq_tls.py` | Adds the hybrid ML-KEM group and the TLS exporter to aioquic |
| `demo.py` | The scenario suite |
| `crosscheck_*.py` | Cross-validation of the post-quantum primitives against liboqs |

## Key design decisions and findings

| | Decision or finding |
|---|---|
| D1 | Build on standard QUIC rather than a new transport. AETHER v0.1's native packet format is deferred |
| D2 | Licensing is a credential class, not a protocol frame, and never gates safety, audit, revocation or halt |
| D4 | Capability advertisement (`CAPABILITY_AD`, non-authoritative) is separated from delegated authority (`DELEGATE`) |
| D5 | Early data is limited to read-only (R0) messages |
| D6 | Inference steps and knowledge deltas are opt-in and treated as untrusted data |
| D7 | Every message type must define a human-readable rendering |
| D8 | All signatures are hybrid Ed25519 + ML-DSA-65; both must verify and there is no classical fallback |
| D9 | Datagram envelopes are unsigned and rely on the authenticated session (R0 only, not forwardable), because a signed envelope is about 5.8 KB and cannot fit a datagram |

Other findings from building it:

- Post-quantum signatures make every sealed object roughly 14 times larger (about 5.8 KB versus 0.4 KB).
- ML-DSA signing is randomised, so revocation identifiers must hash the signed body, not the signature.
- aioquic enables the QUIC spin bit by default, which conflicts with the privacy goals; v2 and v3 pin it off.

## Limitations

- **Not production crypto.** `kyber-py` and `dilithium-py` are pure Python: correct against liboqs, but not
  constant-time and not audited. `pq_tls.py` source-patches aioquic 1.7.2 (pinned), a prototyping technique
  only. A real deployment needs a TLS stack with native hybrid support, such as OpenSSL 3.5+ or aws-lc.
- **The hybrid TLS group has not been tested against another TLS implementation.** Both ends are this code.
- **The composite signature construction is ad hoc.** It is two independent signatures, both required, not a
  standardised composite scheme.
- **No formal verification.** The PRESENT handshake has not been modelled in Tamarin or ProVerif.
- **TLS certificates are still classical**, ephemeral and deliberately untrusted. Identity comes from the
  hybrid-signed, channel-bound presentation.
- **Simplified trust infrastructure.** One registry authority, a shared fake clock, flag-based safe-state reset,
  no offline-host recovery, no PQ key rotation, no selective disclosure.
- **Not covered:** connection migration, padding and cover traffic, ontology negotiation, and covert channels
  through free-form payload text.
- **"Early data" is a policy flag**, not real TLS 0-RTT.

## Roadmap

1. Apply amendments D8 and D9 to the specification document.
2. Formally model the PRESENT handshake and channel binding (Tamarin or ProVerif).
3. Interoperability test of the hybrid TLS group against OpenSSL 3.5 or BoringSSL.
4. Replace pure-Python primitives with liboqs or aws-lc bindings.
5. Standardised composite signatures once the IETF work settles.
6. Offline-host behaviour, PQ key rotation, and a schema registry with CDDL definitions.
7. Gateways to MCP and A2A.

## Lineage

- **AETHER Protocol v0.1**: the QUIC-derived agent transport draft, produced with Grok.
- **Mevrsic Trust Authority (MTA) v0.1**: the decentralised trust framework for embodied AI that supplies the
  identity, credential, delegation, revocation and assurance model.
- The unified specification (v0.2) merges both with a layered messaging architecture developed in discussion
  with Claude.

Built on [aioquic](https://github.com/aiortc/aioquic), [cryptography](https://cryptography.io),
[cbor2](https://github.com/agronholm/cbor2), [kyber-py](https://github.com/GiacomoPope/kyber-py) and
[dilithium-py](https://github.com/GiacomoPope/dilithium-py), with [liboqs](https://openquantumsafe.org) used
for cross-checking.

## Contributing and security

Issues and discussion are welcome. This is a research prototype, so please do not report the limitations
listed above as vulnerabilities. For anything else security-relevant, contact [maintainer contact].

## License

GNU General Public License v3.0
