"""Reproduce the 64-byte DER ECDSA test vector, without random signing.

Test-only affine P-256 arithmetic; never use this code or its keys in production.
Choose short r and s, then recover a public key for that signature/message:
Q = r^-1 (sR - zG). The private key of Q is not known or needed. A fixed,
throwaway Ed25519 issuer signs the certificate containing Q (not a TLS PKI).
Requires Python cryptography; writes the two fixtures beside this script.
"""
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.x509.oid import NameOID

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
NONCE = b"cf954b673d4aa6e859a1ac77f9442cd217de4f3e39c95aebcc8bf6652abafe6a"


def add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3 * x * x - 3) * pow(2 * y, -1, P) if left == right
             else (v - y) * pow(u - x, -1, P)) % P
    result_x = (slope * slope - x - u) % P
    return result_x, (slope * (x - result_x) - y) % P


def multiply(scalar, point):
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


# Both integers occupy 29 bytes, yielding a 64-byte DER SEQUENCE.
r = 1 << 224
while True:
    squared_y = (r**3 - 3 * r + B) % P
    y = pow(squared_y, (P + 1) // 4, P)
    if y * y % P == squared_y:
        break
    r += 1
s = (1 << 224) + 1
z = int.from_bytes(sha256(NONCE).digest(), "big")
public_point = multiply(pow(r, -1, N), add(multiply(s, (r, y)), multiply(-z % N, G)))
public_key = ec.EllipticCurvePublicNumbers(*public_point, ec.SECP256R1()).public_key()
signature = utils.encode_dss_signature(r, s)
assert len(signature) == 64
public_key.verify(signature, NONCE, ec.ECDSA(hashes.SHA256()))
issuer = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
certificate = (x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "short-der.test")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "throwaway-test-issuer")]))
    .public_key(public_key)
    .serial_number(1)
    .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
    .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
    .sign(issuer, None))
folder = Path(__file__).resolve().parent
(folder / "ec_short_der_leaf.der").write_bytes(certificate.public_bytes(serialization.Encoding.DER))
(folder / "ec_short_der_signature.der").write_bytes(signature)
