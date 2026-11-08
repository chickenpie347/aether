"""
AETHER-Q transport profile (spec section 4): the protocol core over real QUIC v1.

  * ALPN `aether/1`, hybrid X25519+ML-KEM-768 key exchange only (see pq_tls.py).
  * Control stream = first client-initiated bidirectional stream (stream 0): HELLO, PRESENT, DELEGATE.
  * Message streams: one fresh bidirectional stream per envelope exchange (request -> RECEIPT, then FIN).
  * QUIC DATAGRAMs: loss-tolerant R0 envelopes (e.g. HEARTBEAT), no receipt.
  * TLS certificates are ephemeral and self-signed and are NOT trusted. Agent identity comes from
    PRESENT, signed over the TLS exporter of the live connection (channel binding). A man-in-the-middle
    that terminates TLS on both sides gets a different exporter on each leg, so the binding fails.
"""
import asyncio
import contextlib
import datetime
import socket
import ssl

import pq_tls

pq_tls.install()  # must run before aioquic.quic / aioquic.asyncio are imported

from aioquic.asyncio import QuicConnectionProtocol, serve  # noqa: E402
from aioquic.quic.configuration import QuicConfiguration  # noqa: E402
from aioquic.quic.connection import QuicConnection  # noqa: E402
from aioquic.quic.events import (  # noqa: E402
    ConnectionTerminated, DatagramFrameReceived, HandshakeCompleted, StreamDataReceived,
)
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from aether_poc import (  # noqa: E402
    HOST_ACTIONS, Agent, HostSession, Result, dec, enc, h, make_envelope, make_present, seal_ok,
    verify_present,
)

ALPN = "aether/1"
tls = pq_tls.tls_module


class NoSpinQuicConnection(QuicConnection):
    """Spec 4.3: the QUIC spin bit MUST be disabled (it lets on-path observers measure RTT per flow).
    aioquic reflects it by default, so pin it to zero with a property that ignores writes."""

    @property
    def _spin_bit(self):
        return False

    @_spin_bit.setter
    def _spin_bit(self, _value):
        pass


import aioquic.asyncio.server as _aioquic_server  # noqa: E402

_aioquic_server.QuicConnection = NoSpinQuicConnection  # server-side connections too


def framed(frame: dict) -> bytes:
    raw = enc(frame)
    return len(raw).to_bytes(4, "big") + raw


class QuicChannel:
    """Exposes the live connection's TLS exporter to the protocol core (channel binding)."""

    def __init__(self, quic: QuicConnection):
        self._quic = quic

    def exporter(self, label: bytes) -> bytes:
        return self._quic.tls.export_keying_material(b"EXPORTER-" + label, b"", 32)

    @property
    def key_exchange_group(self) -> int:
        return self._quic.tls.key_exchange_group


def _ephemeral_cert():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aether-ephemeral")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    return cert, key


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class AetherProtocol(QuicConnectionProtocol):
    """One class for both roles. With `host` set it is the server side; otherwise it queues
    incoming frames per stream for the client to await."""

    def __init__(self, *args, host=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.host = host
        self.hsess: HostSession | None = None
        self._bufs: dict[int, bytearray] = {}
        self._queues: dict[int, asyncio.Queue] = {}
        self.terminated: str | None = None

    # -- events ---------------------------------------------------------------------------
    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            if self.host is not None:
                self.hsess = HostSession(QuicChannel(self._quic))
                self.host.sessions.append(self.hsess)
        elif isinstance(event, StreamDataReceived):
            buf = self._bufs.setdefault(event.stream_id, bytearray())
            buf += event.data
            while len(buf) >= 4:
                n = int.from_bytes(buf[:4], "big")
                if len(buf) < 4 + n:
                    break
                frame = dec(bytes(buf[4:4 + n]))
                del buf[:4 + n]
                self._on_frame(event.stream_id, frame, event.end_stream)
        elif isinstance(event, DatagramFrameReceived):
            if self.host is not None and self.hsess is not None:
                self.host.on_datagram(self.hsess, event.data)
        elif isinstance(event, ConnectionTerminated):
            self.terminated = event.reason_phrase or f"error {event.error_code}"
            for q in self._queues.values():
                q.put_nowait(None)

    def _on_frame(self, sid: int, frame: dict, end_stream: bool):
        if self.host is not None:
            outs = self.host.on_frame(self.hsess, frame)
            for i, out in enumerate(outs):
                last = i == len(outs) - 1
                fin = (sid != 0 and last) or out.get("t") == "CLOSE"
                self.send_frame(sid, out, end_stream=fin)
            if any(o.get("t") == "CLOSE" for o in outs):
                self._loop.call_later(0.1, lambda: self._quic.close(error_code=0x0101, reason_phrase="auth_failed"))
                self.transmit()
        else:
            self._queues.setdefault(sid, asyncio.Queue()).put_nowait(frame)

    def send_frame(self, sid: int, frame: dict, end_stream: bool = False):
        self._quic.send_stream_data(sid, framed(frame), end_stream=end_stream)
        self.transmit()

    # -- client helpers -------------------------------------------------------------------
    async def rpc(self, frame: dict, sid: int | None = None, count: int = 1, timeout: float = 10.0):
        """Send one frame on `sid` (a fresh stream if None) and await `count` response frames."""
        fresh = sid is None
        if fresh:
            sid = self._quic.get_next_available_stream_id()
        q = self._queues.setdefault(sid, asyncio.Queue())
        self.send_frame(sid, frame, end_stream=fresh)
        out = []
        for _ in range(count):
            r = await asyncio.wait_for(q.get(), timeout)
            if r is None:
                return None
            out.append(r)
        return out[0] if count == 1 else out


# ----------------------------------------------------------------------------- server
async def start_host(host, port: int | None = None):
    """Start a QUIC server for a Host. Returns (server, (ip, port))."""
    cert, key = _ephemeral_cert()
    cfg = QuicConfiguration(is_client=False, alpn_protocols=[ALPN], max_datagram_frame_size=65536)
    cfg.certificate, cfg.private_key = cert, key
    port = port or _free_port()
    server = await serve("127.0.0.1", port, configuration=cfg,
                         create_protocol=lambda *a, **k: AetherProtocol(*a, host=host, **k))
    return server, ("127.0.0.1", port)


# ----------------------------------------------------------------------------- client
@contextlib.asynccontextmanager
async def connect4(addr, protocol_cls=AetherProtocol, **proto_kwargs):
    """IPv4 QUIC client (aioquic's own helper insists on a dual-stack socket)."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=[ALPN], verify_mode=ssl.CERT_NONE,
                            max_datagram_frame_size=65536)
    cfg.server_name = addr[0]
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, proto = await loop.create_datagram_endpoint(
        lambda: protocol_cls(NoSpinQuicConnection(configuration=cfg), **proto_kwargs), sock=sock)
    try:
        proto.connect(addr)
        await asyncio.wait_for(proto.wait_connected(), 10)
        yield proto
    finally:
        proto.close()
        try:
            await asyncio.wait_for(proto.wait_closed(), 3)
        except Exception:
            pass
        transport.close()


class QuicClientSession:
    def __init__(self, agent, stack, proto, chan, host_did):
        self.agent, self.stack, self.proto, self.chan, self.host_did = agent, stack, proto, chan, host_did
        self.id = h(chan.exporter(b"session"))[:16]
        self.last_present = None
        self.last_env_frame = None

    async def delegate(self, chain, admin_cred) -> Result:
        r = await self.proto.rpc({"t": "DELEGATE", "chain": chain, "admin_cred": admin_cred}, sid=0)
        if r is None:
            return Result("CLOSED", "connection closed", False)
        return Result("ACCEPTED" if r["t"] == "ACK" else "DENIED", r.get("reason", "ok"), True)

    def _env(self, mtype, perf, risk, payload, epi=None, signed=True):
        return make_envelope(self.agent.e, self.agent.clock, to=[self.host_did], session=self.id,
                             mtype=mtype, perf=perf, risk=risk, payload=payload,
                             epoch=self.agent.view.epoch, epi=epi, signed=signed)

    async def send_env(self, mtype, perf, risk, payload, epi=None, early=False) -> Result:
        return await self.send_raw_env(self._env(mtype, perf, risk, payload, epi), early)

    async def send_raw_env(self, env, early=False) -> Result:
        """Each envelope exchange rides its own QUIC stream (spec 4.2)."""
        self.last_env_frame = {"t": "ENVELOPE", "env": env, "early": early}
        r = await self.proto.rpc(self.last_env_frame)
        if r is None or r["t"] != "RECEIPT":
            return Result("CLOSED", (r or {}).get("code", "connection closed"), False)
        rc = r["receipt"]
        return Result(rc["body"]["outcome"], rc["body"]["reason"], seal_ok(rc) and rc["by"] == self.host_did)

    async def call(self, action, params, risk=None, early=False) -> Result:
        return await self.send_env("TOOL_CALL", "request", risk or HOST_ACTIONS[action],
                                   {"action": action, "params": params}, early=early)

    def send_datagram(self, mtype, perf, risk, payload):
        """Fire-and-forget over a QUIC DATAGRAM frame; no receipt."""
        env = self._env(mtype, perf, risk, payload, signed=False)  # D9: session-authenticated, unsigned
        self.proto._quic.send_datagram_frame(enc({"t": "ENVELOPE", "env": env}))
        self.proto.transmit()

    async def close(self):
        await self.stack.aclose()


class QuicAgent(Agent):
    async def connect(self, addr, creds=None, raw_present=None) -> QuicClientSession:
        """HELLO -> verify host PRESENT -> send own PRESENT. `raw_present` injects a captured frame."""
        stack = contextlib.AsyncExitStack()
        try:
            proto = await stack.enter_async_context(connect4(addr))
            chan = QuicChannel(proto._quic)
            hello, hp = await proto.rpc({"t": "HELLO", "v": [1], "profile": "aether-q",
                                         "cap_ad": {"authoritative": False}}, sid=0, count=2)
            ok, why, hcreds = verify_present(self.view, self.clock, hp, chan, "server")
            if not ok or "DeviceRegistration" not in hcreds:
                raise ConnectionError(f"host failed verification: {why}")
            frame = raw_present or make_present(self.e, creds if creds is not None else self.creds, chan, "client")
            resp = await proto.rpc(frame, sid=0)
            if resp is None or resp["t"] != "ACK":
                raise ConnectionError(f"{(resp or {}).get('code', 'closed')}: {(resp or {}).get('reason', proto.terminated)}")
        except BaseException:
            await stack.aclose()
            raise
        cs = QuicClientSession(self, stack, proto, chan, hp["did"])
        cs.last_present = frame
        return cs


# ----------------------------------------------------------------------------- MITM relay (for tests)
class RelayProtocol(AetherProtocol):
    """An attacker that terminates the victim's QUIC connection and re-originates a second one to the
    real host, forwarding frames verbatim. TLS is unauthenticated, so it succeeds at the transport level."""

    def __init__(self, *args, upstream=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.upstream = upstream

    def _on_frame(self, sid, frame, end_stream):
        asyncio.ensure_future(self._forward(sid, frame))

    async def _forward(self, sid, frame):
        count = 2 if frame.get("t") == "HELLO" else 1
        outs = await self.upstream.rpc(frame, sid=0, count=count)
        for o in (outs if isinstance(outs, list) else [outs]):
            if o is not None:
                self.send_frame(sid, o)


async def start_mitm_relay(host_addr):
    """Returns (relay_addr, closer)."""
    stack = contextlib.AsyncExitStack()
    upstream = await stack.enter_async_context(connect4(host_addr))
    cert, key = _ephemeral_cert()
    cfg = QuicConfiguration(is_client=False, alpn_protocols=[ALPN], max_datagram_frame_size=65536)
    cfg.certificate, cfg.private_key = cert, key
    port = _free_port()
    server = await serve("127.0.0.1", port, configuration=cfg,
                         create_protocol=lambda *a, **k: RelayProtocol(*a, upstream=upstream, **k))

    async def closer():
        server.close()
        await stack.aclose()
    return ("127.0.0.1", port), closer
