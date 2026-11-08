"""
pq_tls: hybrid post-quantum key exchange for aioquic (spec decision D1).

aioquic 1.7.2 has no ML-KEM support, so this module loads a patched copy of aioquic.tls in
its place. The patch adds:

  1. The X25519MLKEM768 hybrid group (IANA codepoint 0x11EC) to the TLS 1.3 handshake:
       client key share = ML-KEM-768 encapsulation key (1184 B) || X25519 public key (32 B)
       server key share = ML-KEM-768 ciphertext        (1088 B) || X25519 public key (32 B)
       shared secret    = ML-KEM shared secret (32 B)  || X25519 shared secret (32 B)
  2. A PQ-only default: endpoints advertise only the hybrid group, so a classical-only peer is
     refused during the handshake (spec 4.1).
  3. RFC 8446 section 7.5 exporter (export_keying_material), needed for channel binding. aioquic
     does not expose one.

ML-KEM comes from kyber-py (pure Python, FIPS 203 sizes). It was cross-checked against liboqs in
both directions (see crosscheck_mlkem.py), but it is not constant-time or audited. A production
build should use liboqs or OpenSSL 3.5+.

Call install() BEFORE importing anything from aioquic.quic or aioquic.asyncio.
"""
import pathlib
import sys
import types

import aioquic

PINNED_VERSION = "1.7.2"

_EXPORTER_METHOD = '''    def export_keying_material(self, label: bytes, context: bytes = b"", length: int = 32) -> bytes:
        """RFC 8446 section 7.5 TLS exporter."""
        if self.exporter_master_secret is None:
            raise RuntimeError("handshake has not reached the exporter secret yet")
        alg = self.key_schedule.algorithm
        empty = hashes.Hash(alg)
        empty.update(b"")
        derived = hkdf_expand_label(alg, self.exporter_master_secret, label, empty.finalize(), alg.digest_size)
        ctx = hashes.Hash(alg)
        ctx.update(context)
        return hkdf_expand_label(alg, derived, b"exporter", ctx.finalize(), length)

    def _client_send_hello(self, output_buf: Buffer) -> None:'''

_CLIENT_SHARE = '''            elif group == Group.X25519MLKEM768:
                _ek, self._mlkem_dk = _MLKEM.keygen()
                self._hybrid_x25519 = x25519.X25519PrivateKey.generate()
                key_share.append(
                    (
                        Group.X25519MLKEM768,
                        _ek + self._hybrid_x25519.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                    )
                )
                supported_groups.append(Group.X25519MLKEM768)
            elif group == Group.GREASE:
                key_share.append((Group.GREASE, b"\\x00"))'''

_CLIENT_KEX = '''        shared_key: bytes | None = None
        self.key_exchange_group = peer_hello.key_share[0]
        try:
            if peer_hello.key_share[0] == Group.X25519MLKEM768:
                _d = peer_hello.key_share[1]
                if len(_d) != 1088 + 32 or self._mlkem_dk is None:
                    raise ValueError("bad hybrid server share")
                _ss_pq = _MLKEM.decaps(self._mlkem_dk, _d[:1088])
                _ss_x = self._hybrid_x25519.exchange(x25519.X25519PublicKey.from_public_bytes(_d[1088:]))
                shared_key = _ss_pq + _ss_x
                peer_public_key = None
            else:
                peer_public_key = decode_public_key(peer_hello.key_share)
'''

_SERVER_KEX = '''        shared_key: bytes | None = None
        _server_share = None
        try:
            for key_share in peer_hello.key_share:
                if key_share[0] not in self._supported_groups:
                    continue
                if key_share[0] == Group.X25519MLKEM768:
                    _d = key_share[1]
                    if len(_d) != 1184 + 32:
                        raise ValueError("bad hybrid client share")
                    _ss_pq, _ct = _MLKEM.encaps(_d[:1184])
                    _sk = x25519.X25519PrivateKey.generate()
                    _ss_x = _sk.exchange(x25519.X25519PublicKey.from_public_bytes(_d[1184:]))
                    shared_key = _ss_pq + _ss_x
                    self.key_exchange_group = Group.X25519MLKEM768
                    _server_share = (
                        Group.X25519MLKEM768,
                        _ct + _sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                    )
                    break
                peer_public_key = decode_public_key(key_share)
'''

_GROUP_SETUP = '''        if default_backend().x448_supported():
            self._supported_groups.append(Group.X448)
        if is_client and CLIENT_GROUPS_OVERRIDE is not None:
            self._supported_groups = list(CLIENT_GROUPS_OVERRIDE)  # test hook: simulate a classical-only client
        else:
            self._supported_groups = [Group.X25519MLKEM768]  # PQ-only: classical-only peers are refused
'''

_EXPORTER_SAVE = "\n        self.exporter_master_secret = self.key_schedule.derive_secret(b\"exp master\")"

PATCHES = [
    ("class Group(IntEnum):\n    SECP256R1 = 0x0017\n",
     "from kyber_py.ml_kem import ML_KEM_768 as _MLKEM\n\nCLIENT_GROUPS_OVERRIDE = None\n\n\n"
     "class Group(IntEnum):\n    X25519MLKEM768 = 0x11EC\n    SECP256R1 = 0x0017\n"),
    ("class Context:\n", "class Context:\n    key_exchange_group = None\n    exporter_master_secret = None\n    _mlkem_dk = None\n\n"),
    ("        if default_backend().x448_supported():\n            self._supported_groups.append(Group.X448)\n", _GROUP_SETUP),
    ("    def _client_send_hello(self, output_buf: Buffer) -> None:", _EXPORTER_METHOD),
    ('            elif group == Group.GREASE:\n                key_share.append((Group.GREASE, b"\\x00"))', _CLIENT_SHARE),
    ("        shared_key: bytes | None = None\n        try:\n            peer_public_key = decode_public_key(peer_hello.key_share)\n", _CLIENT_KEX),
    ("        shared_key: bytes | None = None\n        try:\n            for key_share in peer_hello.key_share:\n"
     "                if key_share[0] not in self._supported_groups:\n                    continue\n"
     "                peer_public_key = decode_public_key(key_share)\n", _SERVER_KEX),
    ("            key_share=encode_public_key(public_key),\n            pre_shared_key=pre_shared_key,",
     "            key_share=(_server_share or encode_public_key(public_key)),\n            pre_shared_key=pre_shared_key,"),
    ('        self.key_schedule.extract(None)\n        self._setup_traffic_protection(\n            Direction.DECRYPT, Epoch.ONE_RTT, b"s ap traffic"\n        )',
     '        self.key_schedule.extract(None)' + _EXPORTER_SAVE + '\n        self._setup_traffic_protection(\n            Direction.DECRYPT, Epoch.ONE_RTT, b"s ap traffic"\n        )'),
    ('        self.key_schedule.extract(None)\n        self._setup_traffic_protection(\n            Direction.ENCRYPT, Epoch.ONE_RTT, b"s ap traffic"\n        )',
     '        self.key_schedule.extract(None)' + _EXPORTER_SAVE + '\n        self._setup_traffic_protection(\n            Direction.ENCRYPT, Epoch.ONE_RTT, b"s ap traffic"\n        )'),
]

tls_module = None


def install():
    """Replace aioquic.tls with the patched copy. Idempotent."""
    global tls_module
    if tls_module is not None:
        return tls_module
    if aioquic.__version__ != PINNED_VERSION:
        raise RuntimeError(f"pq_tls is pinned to aioquic {PINNED_VERSION}, found {aioquic.__version__}")
    if "aioquic.tls" in sys.modules or "aioquic.quic.connection" in sys.modules:
        raise RuntimeError("pq_tls.install() must run before aioquic.quic or aioquic.asyncio is imported")
    path = pathlib.Path(aioquic.__file__).with_name("tls.py")
    src = path.read_text()
    for old, new in PATCHES:
        if src.count(old) != 1:
            raise RuntimeError(f"patch anchor not found exactly once: {old[:60]!r}")
        src = src.replace(old, new)
    mod = types.ModuleType("aioquic.tls")
    mod.__package__ = "aioquic"
    mod.__file__ = str(path)
    sys.modules["aioquic.tls"] = mod
    exec(compile(src, "aioquic/tls.py (pq-patched)", "exec"), mod.__dict__)
    tls_module = mod
    return mod
