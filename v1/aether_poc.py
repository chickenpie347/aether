"""
AETHER Suite - Proof of Concept (v0.2 spec)

Implements the spec's core mechanics end to end over a real localhost socket:

  * Transport shim (stand-in for QUIC + hybrid PQ TLS): X25519 key exchange, ChaCha20-Poly1305
    framing, and a TLS-exporter-style secret used for channel binding.
  * Trust plane: DIDs, signed credentials, scoped issuer registry, revocation, epochs.
  * Session frames: HELLO, PRESENT (channel-bound), DELEGATE, ENVELOPE, RECEIPT.
  * Authority: attenuating delegation chains with caveats.
  * Envelope: deterministic CBOR, signed, causal parents, epistemic block.
  * Enforcement boundary: a host-local safety controller independent of all remote trust state.
  * Assurance: hash-chained audit log, human-legible rendering, HALT, RETRACT.

NOT production crypto. Deliberate stand-ins, all replaceable per the spec:
  Ed25519          -> ML-DSA / SLH-DSA (hybrid)
  X25519           -> X25519 + ML-KEM-768 hybrid inside QUIC/TLS 1.3
  did:aether:<key> -> did:key / did:web / did:peer / ledger-anchored DIDs
  JSON-ish creds   -> W3C Verifiable Credentials
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import struct
from collections import namedtuple

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

RISK = {"R0": 0, "R1": 1, "R2": 2}
STATUS_RANK = {"speculative": 0, "assumed": 1, "inferred": 2, "reported": 3, "observed": 4}
# Spec 10.4 default maximum registry staleness (seconds) per risk class
STALENESS = {"R0": 24 * 3600, "R1": 3600, "R2": 300}
NAMES: dict[str, str] = {}


# ----------------------------------------------------------------------------- primitives
def enc(obj) -> bytes:
    """Deterministic CBOR (RFC 8949 section 4.2)."""
    return cbor2.dumps(obj, canonical=True)


def dec(raw: bytes):
    return cbor2.loads(raw)


def h(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def nm(did: str) -> str:
    return NAMES.get(did, did[-8:])


class Clock:
    """Injectable clock so freshness behaviour is deterministic."""

    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class Entity:
    def __init__(self, name: str):
        self.name = name
        self._sk = ed25519.Ed25519PrivateKey.generate()
        self.pub = self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.did = "did:aether:" + self.pub.hex()
        NAMES[self.did] = name

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)


def _verify(did: str, data: bytes, sig: bytes) -> bool:
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(did.split(":")[2]))
        pub.verify(sig, data)
        return True
    except (InvalidSignature, ValueError, IndexError, TypeError):
        return False


def seal(entity: Entity, body: dict) -> dict:
    return {"body": body, "by": entity.did, "sig": entity.sign(enc(body))}


def seal_ok(obj) -> bool:
    try:
        return _verify(obj["by"], enc(obj["body"]), obj["sig"])
    except (KeyError, TypeError):
        return False


# ----------------------------------------------------------------------------- trust plane
def issue_credential(issuer: Entity, ctype: str, subject: str, claims: dict, clock: Clock, ttl: float = 86400):
    body = {
        "id": os.urandom(8).hex(), "type": ctype, "iss": issuer.did, "sub": subject,
        "claims": claims, "nbf": clock.now(), "exp": clock.now() + ttl,
    }
    return seal(issuer, body)


class TrustRegistry:
    """Authoritative registry: scoped issuer recognition, suspension, revocation, epochs."""

    def __init__(self, authority: Entity, clock: Clock):
        self.authority, self.clock = authority, clock
        self.issuers: dict[str, dict] = {}
        self.revoked: list[str] = []
        self.epoch = 1

    def recognise(self, issuer: Entity, scopes: list[str]) -> None:
        self.issuers[issuer.did] = {"scopes": sorted(scopes), "suspended": False}
        self.epoch += 1

    def suspend(self, issuer: Entity) -> None:
        self.issuers[issuer.did]["suspended"] = True
        self.epoch += 1

    def revoke(self, cred_or_link_id: str) -> None:
        self.revoked.append(cred_or_link_id)
        self.epoch += 1

    def snapshot(self) -> dict:
        body = {"epoch": self.epoch, "issuers": dec(enc(self.issuers)),
                "revoked": sorted(self.revoked), "ts": self.clock.now()}
        return seal(self.authority, body)


class RegistryView:
    """A relying party's local copy of the registry. Pre-shared trust anchor, no rollback."""

    def __init__(self, anchor_did: str, clock: Clock):
        self.anchor, self.clock = anchor_did, clock
        self.snap: dict | None = None
        self.received_at: float | None = None

    def apply(self, sealed: dict) -> bool:
        if sealed.get("by") != self.anchor or not seal_ok(sealed):
            return False
        b = sealed["body"]
        if self.snap and (b["epoch"], b["ts"]) <= (self.snap["epoch"], self.snap["ts"]):
            return False  # rollback or replay of an old snapshot
        self.snap, self.received_at = b, self.clock.now()
        return True

    @property
    def epoch(self) -> int:
        return self.snap["epoch"] if self.snap else 0

    def staleness(self) -> float:
        return float("inf") if self.received_at is None else self.clock.now() - self.received_at

    def issuer_ok(self, did: str, ctype: str) -> bool:
        if not self.snap:
            return False
        e = self.snap["issuers"].get(did)
        return bool(e) and not e["suspended"] and ctype in e["scopes"]

    def is_revoked(self, ident: str) -> bool:
        return bool(self.snap) and ident in self.snap["revoked"]


def verify_credential(view: RegistryView, clock: Clock, cred: dict, ctype: str | None = None):
    if not seal_ok(cred):
        return False, "bad signature"
    b = cred["body"]
    if cred["by"] != b["iss"]:
        return False, "issuer mismatch"
    if ctype and b["type"] != ctype:
        return False, f"expected {ctype}, got {b['type']}"
    if not view.issuer_ok(b["iss"], b["type"]):
        return False, f"issuer {nm(b['iss'])} not recognised (or suspended) for scope {b['type']}"
    if view.is_revoked(b["id"]):
        return False, "credential revoked"
    if not (b["nbf"] <= clock.now() <= b["exp"]):
        return False, "credential not currently valid"
    return True, "ok"


# ----------------------------------------------------------------------------- authority
def link_id(link: dict) -> str:
    return h(enc(link))[:16]


def make_link(issuer: Entity, subject: str, caveats: dict, parent: dict | None = None) -> dict:
    body = {"iss": issuer.did, "sub": subject, "caveats": caveats,
            "parent": h(enc(parent)) if parent else None}
    return seal(issuer, body)


def attenuates(parent: dict, child: dict) -> str | None:
    """Return None if child is a valid narrowing of parent, else the reason it is not."""
    if child["host"] != parent["host"]:
        return "host scope changed"
    if parent["max_depth"] < 1:
        return "delegation depth exhausted"
    if child["max_depth"] > parent["max_depth"] - 1:
        return "max_depth not reduced"
    if not set(child["actions"]) <= set(parent["actions"]):
        return "actions broadened"
    if RISK[child["max_risk"]] > RISK[parent["max_risk"]]:
        return "risk ceiling raised"
    if child["not_after"] > parent["not_after"]:
        return "lifetime extended"
    for act, lims in parent["param_max"].items():
        if act in child["actions"]:
            cl = child["param_max"].get(act, {})
            for k, v in lims.items():
                if k not in cl or cl[k] > v:
                    return f"limit {act}.{k} loosened or dropped"
    return None


def verify_chain(view, clock, chain, admin_cred, host_did, sender_did):
    ok, why = verify_credential(view, clock, admin_cred, "Administrator")
    if not ok:
        return False, "administrator credential: " + why, None
    ab = admin_cred["body"]
    if ab["claims"].get("host") != host_did:
        return False, "administrator credential is for a different host", None
    if not chain:
        return False, "empty chain", None
    prev, prev_sub = None, ab["sub"]
    for i, link in enumerate(chain):
        if not seal_ok(link) or link["by"] != link["body"]["iss"]:
            return False, f"link {i}: bad signature", None
        b = link["body"]
        if b["iss"] != prev_sub:
            return False, f"link {i}: issuer is not the previous holder", None
        if b["parent"] != (h(enc(prev)) if prev else None):
            return False, f"link {i}: parent hash mismatch", None
        if view.is_revoked(link_id(link)):
            return False, f"link {i}: revoked", None
        if prev is None:
            if b["caveats"]["host"] != host_did:
                return False, "root link targets a different host", None
        else:
            why = attenuates(prev["body"]["caveats"], b["caveats"])
            if why:
                return False, f"link {i}: not attenuating ({why})", None
        prev, prev_sub = link, b["sub"]
    if prev_sub != sender_did:
        return False, "chain does not end at the sender", None
    cav = prev["body"]["caveats"]
    if clock.now() > cav["not_after"]:
        return False, "capability expired", None
    return True, "ok", cav


def authorize(cav: dict, action: str, risk: str, params: dict, now: float) -> str | None:
    if now > cav["not_after"]:
        return "capability expired"
    if action not in cav["actions"]:
        return f"action '{action}' not granted"
    if RISK[risk] > RISK[cav["max_risk"]]:
        return f"risk {risk} exceeds ceiling {cav['max_risk']}"
    for k, limit in cav["param_max"].get(action, {}).items():
        if k not in params:
            return f"parameter '{k}' required by caveat"
        if params[k] > limit:
            return f"{k}={params[k]} exceeds caveat limit {limit}"
    return None


# ----------------------------------------------------------------------------- envelope + audit
def make_envelope(sender: Entity, clock: Clock, *, to, session, mtype, perf, risk, payload,
                  epoch=0, parents=(), epi=None, ttl=60) -> dict:
    body = {
        "v": 1, "mid": os.urandom(16).hex(), "thread": os.urandom(8).hex(), "parents": list(parents),
        "from": sender.did, "to": list(to), "session": session, "perf": perf, "mtype": mtype,
        "risk": risk, "ts": clock.now(), "ttl": ttl, "epoch": epoch, "epi": epi, "payload": payload,
    }
    return seal(sender, body)


def render(b: dict) -> str:
    """Human-legible rendering (spec 13.2). Every message type must define one."""
    who, to = nm(b["from"]), ", ".join(nm(t) for t in b["to"])
    p, epi = b["payload"], b.get("epi")
    tail = (f" [{epi['status']}, confidence {epi['confidence']:.2f}]"
            if isinstance(epi, dict) and "status" in epi and isinstance(epi.get("confidence"), (int, float)) else "")
    t = b["mtype"]
    if t == "TOOL_CALL":
        return f"{who} asks {to} to run {p['action']} {p['params']} (risk {b['risk']})"
    if t == "KNOWLEDGE_DELTA":
        return f"{who} tells {to}: '{p['text']}'{tail}"
    if t == "RETRACT":
        return f"{who} retracts claim {p['target']}"
    if t == "INFERENCE_STEP":
        return f"{who} shares an inference step with {to}: '{p['text'][:60]}' (untrusted data){tail}"
    if t == "HALT":
        return f"{who} orders {to} to pause agent {nm(p['target'])}"
    return f"{who} sends {t} to {to}"


class AuditLog:
    """Hash-chained, tamper-evident log (spec 13.1)."""

    def __init__(self):
        self.entries: list[dict] = []

    def append(self, event: dict, rendered: str) -> None:
        prev = self.entries[-1]["hash"] if self.entries else "0" * 64
        body = {"seq": len(self.entries), "event": event, "render": rendered, "prev": prev}
        self.entries.append({**body, "hash": h(enc(body))})

    def verify(self) -> bool:
        prev = "0" * 64
        for i, e in enumerate(self.entries):
            body = {k: e[k] for k in ("seq", "event", "render", "prev")}
            if e["seq"] != i or e["prev"] != prev or e["hash"] != h(enc(body)):
                return False
            prev = e["hash"]
        return True


# ----------------------------------------------------------------------------- transport shim
class SecureChannel:
    """Stand-in for QUIC + hybrid PQ TLS. Provides encryption and an exporter for channel binding."""

    def __init__(self, reader, writer, send_key, recv_key, exporter_secret):
        self.r, self.w = reader, writer
        self._send, self._recv = ChaCha20Poly1305(send_key), ChaCha20Poly1305(recv_key)
        self._sn = self._rn = 0
        self._exp = exporter_secret

    def exporter(self, label: bytes) -> bytes:
        return HKDF(hashes.SHA256(), 32, None, b"EXPORTER-" + label).derive(self._exp)

    async def send(self, frame: dict) -> None:
        ct = self._send.encrypt(self._sn.to_bytes(12, "big"), enc(frame), None)
        self._sn += 1
        self.w.write(struct.pack(">I", len(ct)) + ct)
        await self.w.drain()

    async def recv(self) -> dict | None:
        try:
            n = struct.unpack(">I", await self.r.readexactly(4))[0]
            ct = await self.r.readexactly(n)
        except (asyncio.IncompleteReadError, ConnectionError):
            return None
        pt = self._recv.decrypt(self._rn.to_bytes(12, "big"), ct, None)
        self._rn += 1
        return dec(pt)

    async def close(self) -> None:
        self.w.close()
        try:
            await self.w.wait_closed()
        except Exception:
            pass


async def handshake(reader, writer, initiator: bool) -> SecureChannel:
    sk = x25519.X25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if initiator:
        writer.write(pub)
        await writer.drain()
        peer = await reader.readexactly(32)
        transcript = pub + peer
    else:
        peer = await reader.readexactly(32)
        writer.write(pub)
        await writer.drain()
        transcript = peer + pub
    shared = sk.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
    okm = HKDF(hashes.SHA256(), 96, None, b"aether-poc-v1" + transcript).derive(shared)
    c2s, s2c, exp = okm[:32], okm[32:64], okm[64:]
    return SecureChannel(reader, writer, *((c2s, s2c) if initiator else (s2c, c2s)), exp)


# ----------------------------------------------------------------------------- PRESENT (channel-bound)
def make_present(entity: Entity, creds: list[dict], chan: SecureChannel, role: str) -> dict:
    proof = seal(entity, {"ctx": "aether-present", "role": role,
                          "exporter": chan.exporter(b"present").hex(), "nonce": os.urandom(8).hex()})
    return {"t": "PRESENT", "did": entity.did, "creds": creds, "proof": proof}


def verify_present(view, clock, frame, chan, role):
    p = frame.get("proof")
    if not p or not seal_ok(p) or p["by"] != frame.get("did"):
        return False, "bad presentation proof", {}
    b = p["body"]
    if b["ctx"] != "aether-present" or b["role"] != role:
        return False, "wrong presentation context", {}
    if b["exporter"] != chan.exporter(b"present").hex():
        return False, "channel binding mismatch (relayed or replayed presentation)", {}
    found = {}
    for c in frame.get("creds", []):
        ok, why = verify_credential(view, clock, c)
        if not ok:
            return False, f"credential {c['body']['type']}: {why}", {}
        if c["body"]["sub"] != frame["did"]:
            return False, "credential subject does not match presenter", {}
        found[c["body"]["type"]] = c
    if not found:
        return False, "no credentials presented", {}
    return True, "ok", found


# ----------------------------------------------------------------------------- enforcement boundary
class LocalSafetyController:
    """Host-local controller. Deliberately imports nothing from the trust plane and never
    consults the registry, providers or credentials (spec section 12)."""

    def __init__(self, workspace=((-1, 1), (-1, 1), (0, 1.5)), max_speed=0.5, max_force=20):
        self.workspace, self.max_speed, self.max_force = workspace, max_speed, max_force
        self.safe_state = False

    def enter_safe_state(self) -> None:
        self.safe_state = True

    def validate(self, action: str, params: dict):
        if self.safe_state and action != "arm.read":
            return False, "host is in safe state"
        if action == "arm.move":
            if params["speed"] > self.max_speed:
                return False, f"speed {params['speed']} above hardware limit {self.max_speed}"
            for v, (lo, hi) in zip((params["x"], params["y"], params["z"]), self.workspace):
                if not lo <= v <= hi:
                    return False, "target outside safe workspace"
        if action == "arm.grip" and params["force"] > self.max_force:
            return False, f"force {params['force']} above hardware limit {self.max_force}"
        return True, "ok"


HOST_ACTIONS = {"arm.read": "R0", "knowledge.write": "R0", "inference.share": "R0",
                "log.write": "R1", "arm.move": "R2", "arm.grip": "R2"}
ACTION_OF = {"KNOWLEDGE_DELTA": "knowledge.write", "RETRACT": "knowledge.write",
             "INFERENCE_STEP": "inference.share"}
Result = namedtuple("Result", "outcome reason receipt_ok")


class HostSession:
    def __init__(self, chan):
        self.chan, self.id = chan, h(chan.exporter(b"session"))[:16]
        self.agent = None
        self.creds: dict = {}
        self.chain = self.caveats = self.admin_cred = None
        self.seen: set[str] = set()
        self.dead: str | None = None


class Host:
    def __init__(self, entity: Entity, clock: Clock, anchor_did: str, device_cred: dict):
        self.e, self.clock, self.device_cred = entity, clock, device_cred
        self.view = RegistryView(anchor_did, clock)
        self.controller = LocalSafetyController()
        self.robot = {"pos": [0.0, 0.0, 0.5], "gripper": 0.0}
        self.audit = AuditLog()
        self.claims: dict[str, dict] = {}
        self.untrusted_inbox: list[dict] = []
        self.paused: set[str] = set()
        self.sessions: list[HostSession] = []

    # -- registry updates (EPOCH) ------------------------------------------------------------
    def apply_registry(self, snapshot: dict) -> bool:
        ok = self.view.apply(snapshot)
        if ok:
            self._revalidate()
        return ok

    def _revalidate(self) -> None:
        for s in self.sessions:
            if s.dead or not s.agent:
                continue
            why = self._check_identity(s)
            if why is None and s.chain:
                ok, w, _ = verify_chain(self.view, self.clock, s.chain, s.admin_cred, self.e.did, s.agent)
                why = None if ok else w
            if why:
                s.dead = why
                self.audit.append({"event": "trust_lost", "agent": nm(s.agent), "why": why},
                                  f"Trust lost for {nm(s.agent)}: {why}")
                if s.caveats and s.caveats["max_risk"] == "R2":
                    self.controller.enter_safe_state()
                    self.audit.append({"event": "safe_state"}, "Host entered safe state (R2 authority lost)")

    def _check_identity(self, s: HostSession) -> str | None:
        for ctype in ("AIOperator",):
            c = s.creds.get(ctype)
            if c:
                ok, why = verify_credential(self.view, self.clock, c)
                if not ok:
                    return why
        return None

    # -- connection handling -----------------------------------------------------------------
    async def serve(self, reader, writer):
        chan = await handshake(reader, writer, initiator=False)
        s = HostSession(chan)
        self.sessions.append(s)
        try:
            while True:
                frame = await chan.recv()
                if frame is None:
                    break
                for out in self.on_frame(s, frame):
                    await chan.send(out)
                if frame.get("t") == "CLOSE":
                    break
        except Exception as ex:  # malformed input must never crash the host
            await chan.send({"t": "CLOSE", "code": "protocol_error"})
            self.audit.append({"event": "protocol_error", "err": type(ex).__name__}, f"Protocol error: {ex!r}")
        finally:
            await chan.close()

    def on_frame(self, s: HostSession, f: dict) -> list[dict]:
        t = f.get("t")
        if t == "HELLO":
            return [{"t": "HELLO", "v": 1, "profile": "aether-q-poc", "cap_ad": {"kind": "robot-arm", "authoritative": False}},
                    make_present(self.e, [self.device_cred], s.chan, "server")]
        if t == "PRESENT":
            ok, why, creds = verify_present(self.view, self.clock, f, s.chan, "client")
            if not ok:
                self.audit.append({"event": "present_rejected", "why": why}, f"PRESENT rejected: {why}")
                return [{"t": "CLOSE", "code": "auth_failed", "reason": why}]
            s.agent, s.creds = f["did"], creds
            self.audit.append({"event": "present_ok", "agent": nm(s.agent)}, f"{nm(s.agent)} authenticated")
            return [{"t": "ACK", "what": "PRESENT"}]
        if t == "DELEGATE":
            if not s.agent:
                return [{"t": "CLOSE", "code": "no_session"}]
            ok, why, cav = verify_chain(self.view, self.clock, f["chain"], f["admin_cred"], self.e.did, s.agent)
            self.audit.append({"event": "delegate", "ok": ok, "why": why},
                              f"DELEGATE from {nm(s.agent)}: {'accepted' if ok else 'rejected - ' + why}")
            if not ok:
                return [{"t": "ERROR", "what": "DELEGATE", "reason": why}]
            s.chain, s.admin_cred, s.caveats = f["chain"], f["admin_cred"], cav
            return [{"t": "ACK", "what": "DELEGATE"}]
        if t == "ENVELOPE":
            return [self._on_envelope(s, f["env"], bool(f.get("early")))]
        return []

    # -- the per-message pipeline (spec 10.3) -------------------------------------------------
    def _receipt(self, body: dict, outcome: str, reason: str, result=None) -> dict:
        rb = {"mid": body["mid"], "outcome": outcome, "reason": reason, "ts": self.clock.now(),
              "host": self.e.did, "result": result}
        self.audit.append({"mid": body["mid"][:8], "mtype": body["mtype"], "outcome": outcome, "reason": reason},
                          f"{render(body)} -> {outcome}: {reason}")
        return {"t": "RECEIPT", "receipt": seal(self.e, rb)}

    def _on_envelope(self, s: HostSession, env: dict, early: bool) -> dict:
        body = env.get("body", {})
        if not s.agent:
            return {"t": "CLOSE", "code": "no_session"}
        # 1. signature, sender, session binding, replay, TTL
        if not seal_ok(env) or env["by"] != body.get("from") or body["from"] != s.agent:
            return self._receipt(body, "DENIED", "bad signature or sender mismatch")
        if body["session"] != s.id:
            return self._receipt(body, "DENIED", "session binding mismatch")
        if body["mid"] in s.seen:
            return self._receipt(body, "DENIED", "replayed message id")
        if not body["ts"] <= self.clock.now() <= body["ts"] + body["ttl"]:
            return self._receipt(body, "DENIED", "message expired or from the future")
        s.seen.add(body["mid"])
        mtype, payload = body["mtype"], body["payload"]

        # privileged path: HALT needs a HaltAuthority credential, not a capability chain
        if mtype == "HALT":
            return self._on_halt(s, body)

        # 2. identity still valid under the current registry view
        if s.dead:
            return self._receipt(body, "DENIED", f"trust lost: {s.dead}")
        why = self._check_identity(s)
        if why:
            return self._receipt(body, "DENIED", f"identity invalid: {why}")
        if "AIOperator" not in s.creds:
            return self._receipt(body, "DENIED", "no operator credential")

        # 3. risk class: the host's table is authoritative, a sender cannot understate it
        action = payload["action"] if mtype == "TOOL_CALL" else ACTION_OF.get(mtype)
        if action not in HOST_ACTIONS:
            return self._receipt(body, "DENIED", f"unknown action {action}")
        risk = HOST_ACTIONS[action]
        if RISK[body["risk"]] < RISK[risk]:
            return self._receipt(body, "DENIED", f"risk understated ({body['risk']} < {risk})")
        # 4. early data (0-RTT) is R0 only
        if early and risk != "R0":
            return self._receipt(body, "DENIED", "early data is restricted to R0 messages")
        # 5. freshness policy: stale trust state reduces authority, never expands it
        if RISK[risk] >= 1 and self.view.staleness() > STALENESS[risk]:
            return self._receipt(body, "DENIED", f"registry stale ({self.view.staleness():.0f}s) - restricted to R0")
        # 6. paused agents
        if RISK[risk] >= 1 and s.agent in self.paused:
            return self._receipt(body, "DENIED", "agent paused by HALT")
        # 7. capability chain and caveats
        if not s.chain:
            return self._receipt(body, "DENIED", "no delegation presented")
        ok, why, cav = verify_chain(self.view, self.clock, s.chain, s.admin_cred, self.e.did, s.agent)
        if not ok:
            return self._receipt(body, "DENIED", f"delegation invalid: {why}")
        params = payload.get("params", {}) if mtype == "TOOL_CALL" else {}
        why = authorize(cav, action, risk, params, self.clock.now())
        if why:
            return self._receipt(body, "DENIED", why)

        # 8. dispatch. R1 and R2 additionally pass the local enforcement boundary.
        if mtype == "TOOL_CALL":
            if RISK[risk] >= 1:
                ok, why = self.controller.validate(action, params)
                if not ok:
                    return self._receipt(body, "REFUSED_BY_CONTROLLER", why)
            return self._receipt(body, "EXECUTED", "ok", self._execute(action, params))
        if mtype == "INFERENCE_STEP":
            self.untrusted_inbox.append({"from": nm(s.agent), "text": payload["text"]})
            return self._receipt(body, "STORED_UNTRUSTED", "inference data is never treated as instructions")
        if mtype == "KNOWLEDGE_DELTA":
            return self._on_knowledge(s, body)
        if mtype == "RETRACT":
            return self._on_retract(s, body)
        return self._receipt(body, "DENIED", f"unsupported message type {mtype}")

    def _execute(self, action: str, p: dict):
        if action == "arm.move":
            self.robot["pos"] = [p["x"], p["y"], p["z"]]
        elif action == "arm.grip":
            self.robot["gripper"] = p["force"]
        return {"pos": list(self.robot["pos"]), "gripper": self.robot["gripper"]}

    # -- epistemics (spec section 9) ----------------------------------------------------------
    def _on_knowledge(self, s, body):
        epi, p = body.get("epi"), body["payload"]
        if not epi or epi.get("status") not in STATUS_RANK or not 0 <= epi.get("confidence", -1) <= 1:
            return self._receipt(body, "REJECTED", "epistemic block missing or malformed")
        if epi["status"] == "observed" and not epi.get("evidence"):
            return self._receipt(body, "REJECTED", "status 'observed' requires evidence")
        for parent in epi.get("derived_from", []):
            if parent not in self.claims:
                return self._receipt(body, "REJECTED", f"unknown parent claim {parent}")
            if STATUS_RANK[epi["status"]] > STATUS_RANK[self.claims[parent]["epi"]["status"]]:
                return self._receipt(body, "REJECTED", "status upgraded while forwarding")
        self.claims[p["claim_id"]] = {"by": s.agent, "text": p["text"], "epi": epi,
                                      "derived_from": epi.get("derived_from", []), "retracted": False}
        return self._receipt(body, "ACCEPTED", "claim stored")

    def _on_retract(self, s, body):
        target = body["payload"]["target"]
        c = self.claims.get(target)
        if not c or c["by"] != s.agent:
            return self._receipt(body, "REJECTED", "only the author may retract an existing claim")
        todo, n = [target], 0
        while todo:
            cid = todo.pop()
            if not self.claims[cid]["retracted"]:
                self.claims[cid]["retracted"] = True
                n += 1
            todo += [k for k, v in self.claims.items() if cid in v["derived_from"] and not v["retracted"]]
        return self._receipt(body, "ACCEPTED", f"retracted {n} claim(s) including dependents")

    # -- halt (spec 13.3) ---------------------------------------------------------------------
    def _on_halt(self, s, body):
        c = s.creds.get("HaltAuthority")
        if c:
            ok, why = verify_credential(self.view, self.clock, c)
            if not ok or c["body"]["claims"].get("host") != self.e.did:
                c = None
        if not c:
            return self._receipt(body, "DENIED", "no valid HaltAuthority credential")
        self.paused.add(body["payload"]["target"])
        return self._receipt(body, "HALTED", f"{nm(body['payload']['target'])} moved to pause state")


# ----------------------------------------------------------------------------- client side
class ClientSession:
    def __init__(self, agent, chan, host_did, session_id):
        self.agent, self.chan, self.host_did, self.id = agent, chan, host_did, session_id
        self.last_present = None
        self.last_env_frame = None

    async def _rpc(self, frame):
        await self.chan.send(frame)
        return await self.chan.recv()

    async def delegate(self, chain, admin_cred) -> Result:
        r = await self._rpc({"t": "DELEGATE", "chain": chain, "admin_cred": admin_cred})
        return Result("ACCEPTED" if r["t"] == "ACK" else "DENIED", r.get("reason", "ok"), True)

    async def send_env(self, mtype, perf, risk, payload, epi=None, early=False, to=None) -> Result:
        env = make_envelope(self.agent.e, self.agent.clock, to=to or [self.host_did], session=self.id,
                            mtype=mtype, perf=perf, risk=risk, payload=payload,
                            epoch=self.agent.view.epoch, epi=epi)
        return await self.send_raw_env(env, early)

    async def send_raw_env(self, env, early=False) -> Result:
        self.last_env_frame = {"t": "ENVELOPE", "env": env, "early": early}
        r = await self._rpc(self.last_env_frame)
        if r is None or r["t"] != "RECEIPT":
            return Result("CLOSED", (r or {}).get("code", "connection closed"), False)
        rc = r["receipt"]
        ok = seal_ok(rc) and rc["by"] == self.host_did
        return Result(rc["body"]["outcome"], rc["body"]["reason"], ok)

    async def call(self, action, params, risk=None, early=False) -> Result:
        return await self.send_env("TOOL_CALL", "request", risk or HOST_ACTIONS[action],
                                   {"action": action, "params": params}, early=early)

    async def close(self):
        try:
            await self.chan.send({"t": "CLOSE", "code": "bye"})
        except Exception:
            pass
        await self.chan.close()


class Agent:
    def __init__(self, entity: Entity, clock: Clock, anchor_did: str, creds: list[dict] | None = None):
        self.e, self.clock, self.creds = entity, clock, creds or []
        self.view = RegistryView(anchor_did, clock)

    async def connect(self, addr, creds=None, raw_present=None):
        """Open a session. `raw_present` lets tests inject a captured presentation (relay attack)."""
        r, w = await asyncio.open_connection(*addr)
        chan = await handshake(r, w, initiator=True)
        await chan.send({"t": "HELLO", "v": [1], "profile": "aether-q-poc", "cap_ad": {"authoritative": False}})
        await chan.recv()  # host HELLO
        hp = await chan.recv()
        ok, why, hcreds = verify_present(self.view, self.clock, hp, chan, "server")
        if not ok or "DeviceRegistration" not in hcreds:
            raise ConnectionError(f"host failed verification: {why}")
        frame = raw_present or make_present(self.e, creds if creds is not None else self.creds, chan, "client")
        await chan.send(frame)
        resp = await chan.recv()
        if resp is None or resp["t"] != "ACK":
            await chan.close()
            raise ConnectionError(f"{(resp or {}).get('code')}: {(resp or {}).get('reason')}")
        cs = ClientSession(self, chan, hp["did"], h(chan.exporter(b"session"))[:16])
        cs.last_present = frame
        return cs
