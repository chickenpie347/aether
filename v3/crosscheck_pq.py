"""
Cross-implementation check of the post-quantum primitives against liboqs, both directions:
  ML-KEM-768 (kyber-py, used by pq_tls.py)   and   ML-DSA-65 (dilithium-py, used by aether_poc.py),
the latter with and without the FIPS 204 context string the suite uses (b"aether-poc-v1").

Optional. Needs liboqs + liboqs-python. If liboqs is not in the default location, build a minimal one:

  cmake -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" -DCMAKE_INSTALL_PREFIX=$HOME/_oqs <liboqs-src>
  OQS_INSTALL_PATH=$HOME/_oqs LD_LIBRARY_PATH=$HOME/_oqs/lib python3 crosscheck_pq.py
"""
import sys

from dilithium_py.ml_dsa import ML_DSA_65 as DSA
from kyber_py.ml_kem import ML_KEM_768 as KEM

try:
    import oqs
except Exception as ex:  # noqa: BLE001
    print(f"SKIPPED: liboqs-python unavailable ({type(ex).__name__})")
    sys.exit(0)

N, CTX = 40, b"aether-poc-v1"
res = {"kem fwd": 0, "kem rev": 0, "dsa fwd": 0, "dsa rev": 0, "dsa ctx fwd": 0, "dsa ctx rev": 0}
for i in range(N):
    ek, dk = KEM.keygen()
    with oqs.KeyEncapsulation("ML-KEM-768") as k:
        ct, ss = k.encap_secret(ek)
    res["kem fwd"] += KEM.decaps(dk, ct) == ss
    with oqs.KeyEncapsulation("ML-KEM-768") as k:
        pk = k.generate_keypair()
        ss2, ct2 = KEM.encaps(pk)
        res["kem rev"] += k.decap_secret(ct2) == ss2

    msg = bytes([i]) * 64
    pk, sk = DSA.keygen()
    with oqs.Signature("ML-DSA-65") as v:
        res["dsa fwd"] += v.verify(msg, DSA.sign(sk, msg), pk)
        res["dsa ctx fwd"] += v.verify_with_ctx_str(msg, DSA.sign(sk, msg, ctx=CTX), CTX, pk)
    with oqs.Signature("ML-DSA-65") as s:
        pk2 = s.generate_keypair()
        res["dsa rev"] += DSA.verify(pk2, msg, s.sign(msg))
        res["dsa ctx rev"] += DSA.verify(pk2, msg, s.sign_with_ctx_str(msg, CTX), ctx=CTX)

print(f"liboqs {oqs.oqs_version()} vs kyber-py / dilithium-py, {N} trials each")
for k, v in res.items():
    print(f"  {k:12s} {v}/{N}")
sys.exit(0 if all(v == N for v in res.values()) else 1)
