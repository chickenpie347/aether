# AETHER Suite: Proof of Concept (spec v0.2)

A runnable reference of the spec's core mechanics. A host and several agents talk over a real localhost
socket, and 45 checks assert each claim of the spec.

## Run

```
pip install cbor2 cryptography
python3 demo.py
```

Exit code is non-zero if any check fails. Python 3.10+.

## What it demonstrates

| Spec section | Mechanism | Checks |
|---|---|---|
| 4, 5 | Encrypted transport shim, mutual PRESENT, channel binding | relayed PRESENT rejected |
| 11.3 | Scoped issuer recognition | manufacturer cannot issue operator credentials |
| 10.2 | Attenuating delegation chains | broadened actions, loosened or dropped limits, depth overrun all rejected |
| 10.3 | Per-message verification pipeline | replay, risk understatement, unknown actions, expiry |
| 4.5 | Early data limited to R0 | R2 in 0-RTT refused |
| 10.4 | Freshness policy | stale registry restricts R2, a fresh EPOCH restores it, rollback refused |
| 12 | Enforcement boundary | authorised-but-unsafe action refused by the local controller |
| 9 | Epistemic block, no status upgrade on forwarding, retraction cascade | claim rules enforced |
| 8, 14 | INFERENCE_STEP as untrusted data | injected instruction has no effect |
| 13.3 | HALT | needs a HaltAuthority credential, defined pause state |
| 10.4 | Revocation and provider suspension | sessions cut off, host enters safe state |
| 13.1, 13.2 | Hash-chained audit log, human-readable rendering | tampering detected |

## Files

- `aether_poc.py`: the library (about 750 lines)
- `demo.py`: scenario runner with assertions

## Deliberate stand-ins (all replaceable per the spec)

| PoC | Spec target |
|---|---|
| X25519 + ChaCha20-Poly1305 shim | QUIC v1 with hybrid X25519 + ML-KEM-768 TLS 1.3 (D1) |
| Ed25519 | ML-DSA or SLH-DSA, hybrid during transition |
| `did:aether:<pubkey>` | did:key, did:web, did:peer, ledger-anchored methods |
| CBOR-signed dict credentials | W3C Verifiable Credentials |
| Single in-process registry | Federated registry with governance (MTA Part V) |
| Shared fake clock | Real time with bounded skew |

## Known limits (not yet addressed)

- **Not production crypto.** No formal analysis of the PRESENT handshake. The spec roadmap calls for Tamarin or ProVerif.
- **Single registry authority** signs snapshots. Multi-issuer registry governance, appeals and key rotation are not modelled.
- **No offline behaviour.** The staleness policy fails safe but there is no tested recovery path for disconnected hosts (spec open issue).
- **Safe-state reset** is a flag flipped by the test harness, standing in for an out-of-band administrative channel.
- **No ontology negotiation, selective disclosure, cover traffic, or CID rotation.** The transport shim has no connection migration or multiplexing.
- **Covert channels** through free-form payload text are not mitigated (see spec section 14).
- **Mutation checks** confirmed that disabling channel binding, the attenuation actions check, the freshness policy, the controller, and the risk-understatement check each cause a failing test. Other checks have not been mutation-tested.
