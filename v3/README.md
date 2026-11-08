# AETHER Suite: Proof of Concept v3 (spec v0.2 + amendments D8, D9)

A runnable reference of the spec. A robot host and several agents talk over **real QUIC v1 with hybrid
post-quantum TLS 1.3 (X25519 + ML-KEM-768)**, and every identity, credential, delegation, envelope and
receipt is signed with **hybrid Ed25519 + ML-DSA-65 (FIPS 204)**. 66 checks assert the spec's claims.

## Run

```
pip install -r requirements.txt
python3 demo.py              # 66 checks (about 10 s), non-zero exit on any failure
python3 crosscheck_pq.py     # optional: ML-KEM and ML-DSA vs liboqs (needs liboqs installed)
```

Python 3.10+. IPv4 loopback only.

## What v3 adds

| Spec | Implementation |
|---|---|
| D8: hybrid signatures | `aether_poc.py`: `Entity.sign` produces Ed25519 and ML-DSA-65 signatures; `seal_ok` requires **both** to verify and the exact suite `ed25519+ml-dsa-65`. No classical-only fallback |
| Identity | A DID is now the hash of both public keys (ML-DSA keys are 1952 bytes, too large to embed). Every sealed object carries its key bundle, and verification checks it hashes to the claimed DID |
| Domain separation | Signature input is `aether-seal-v1 || DID || canonical CBOR body`, and ML-DSA uses the FIPS 204 context string `aether-poc-v1` |
| D9: datagram envelopes | Unsigned, authenticated by the session instead (see below) |

## Findings worth knowing

1. **Post-quantum signatures are big.** A signed credential or envelope is about 5.8 KB, versus about 0.4 KB
   unsigned. The ML-DSA signature (3309 B) and public key (1952 B) are 90% of it. PRESENT and DELEGATE frames
   carry several sealed objects, so they run to roughly 10 to 20 KB. QUIC streams handle this, but it matters for any
   constrained link. Caching key bundles per session would save about 2 KB per object (not implemented).
2. **Datagrams cannot carry signed envelopes.** A hybrid-signed envelope is 14 times larger than a QUIC
   datagram. **D9:** datagram envelopes omit the per-message signature and rely on the session: QUIC encrypts and
   authenticates them, and the peer was proven by the channel-bound PRESENT. They are R0-only, never
   forwardable, and the audit log marks them `[datagram, session-authenticated, unsigned]`. They give up
   non-repudiation. Unsigned envelopes are refused on streams.
3. **Randomised signatures break hash-based identifiers.** ML-DSA signing is randomised, so the same grant
   re-signed gets different bytes. Revocation ids and delegation parent hashes therefore hash the signed
   *body*, not the sealed object. Otherwise a key holder could re-sign a revoked grant under a fresh id.

## What the checks prove

Section 5b simulates a **quantum break of Ed25519** by giving the attacker the registrar's Ed25519 private key:

- the forged Administrator credential's Ed25519 half verifies on its own (an Ed25519-only system accepts it)
- the hybrid verifier rejects it, including over the wire in a DELEGATE frame
- the reverse (valid ML-DSA half, forged Ed25519 half) is also rejected, so verification is AND, not OR
- classical-only downgrade, key substitution, body tampering and unsigned stream envelopes are rejected

## Validation performed

- 66 checks pass over real QUIC.
- `crosscheck_pq.py`: `kyber-py` (ML-KEM-768) and `dilithium-py` (ML-DSA-65) agree with liboqs 0.14.0 in both
  directions, 40/40 on each of six tests, including ML-DSA with the context string the suite uses.
- **Mutation checks:** skipping the ML-DSA verification lets the forged Administrator credential through
  (the simulated attack succeeds); skipping the Ed25519 verification, dropping the DID-key binding, hashing
  revocation ids over the signature, and accepting unsigned stream envelopes each cause the intended test to
  fail. The transport and policy mutations from v2 still fail their tests. Other checks have not been
  mutation-tested, and the classical-downgrade check is additionally enforced by a missing-field error, so it
  has no independent mutant.

## Files

| File | Purpose |
|---|---|
| `aether_poc.py` | Transport-independent core: hybrid signatures, trust plane, delegation, envelopes, host pipeline, enforcement boundary, audit |
| `aether_quic.py` | AETHER-Q: QUIC server and client, streams, datagrams, spin-bit pinning, MITM relay for tests |
| `pq_tls.py` | Patches aioquic's TLS: hybrid ML-KEM group, PQ-only policy, TLS exporter |
| `demo.py` | 66 checks across 15 scenarios |
| `crosscheck_pq.py` | Cross-validates ML-KEM and ML-DSA against liboqs |

## Proposed spec amendments (not yet applied to the spec document)

- **D8:** All signatures are hybrid Ed25519 + ML-DSA-65; verifiers MUST require both and MUST refuse any other
  suite. DIDs are self-certifying hashes of both public keys. Signature input is domain-separated.
- **D9:** QUIC datagram envelopes MAY omit the per-message signature. They are session-authenticated, R0-only,
  non-forwardable, and logged as unsigned. Signed envelopes MUST be used for everything else.
- **Revocation and parent identifiers** MUST be computed over the signed body, never the signature.

## Limits and honest caveats

- **Not production crypto.** `kyber-py` and `dilithium-py` are pure Python: correct against liboqs, but not
  constant-time and not audited. `pq_tls.py` source-patches aioquic 1.7.2, a PoC technique. Production should use
  liboqs, aws-lc or OpenSSL 3.5+ and a TLS stack with native hybrid support.
- **The composite signature is ad hoc**: two independent signatures over the same input, both required. It is
  not a standardised composite scheme (the IETF LAMPS composite-signature work is the thing to track). Signing
  uses ML-DSA's default hedged randomisation.
- **Hybrid TLS group not interop-tested** against another TLS stack (both ends are this code).
- **Ed25519 half cannot be dropped yet.** Hybrid is right during transition, but the classical half carries no
  post-quantum value and doubles as the only protection if ML-DSA implementation bugs exist.
- **TLS certificates are still classical (ECDSA P-256)**, ephemeral and deliberately untrusted. Identity comes
  from the hybrid-signed, channel-bound PRESENT, so a quantum-capable active attacker still cannot impersonate.
- **No PQ key rotation, recovery or algorithm-agility rollout** is modelled.
- **"Early data" is a policy flag**, not real TLS 0-RTT.
- **Spin bit** is pinned off by a connection subclass; the check inspects connection state, not captured packets.
- Single registry authority, shared fake clock, flag-based safe-state reset, no offline recovery, no
  selective disclosure, no connection migration, padding or cover traffic. Covert channels through free-form
  payload text are not mitigated. IPv6 not supported by the helper client.
