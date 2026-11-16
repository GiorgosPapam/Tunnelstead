"""Per-instance PKI for OpenVPN (ECDSA P-256 / SHA-256) built on `cryptography`.

Each instance has its own CA, so a certificate from one instance is useless on another. Revocation is enforced
twice: the client's ccd entry is removed (ccd-exclusive) and its serial goes on the CRL.
"""
import base64
import datetime as dt
import hashlib
import os
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_DAYS, SERVER_DAYS, CLIENT_DAYS = 3650, 1825, 825


def _now():
    return dt.datetime.now(dt.UTC)


def _key_pem(k) -> str:
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()


def _cert_pem(c) -> str:
    return c.public_bytes(serialization.Encoding.PEM).decode()


def _ku(ca: bool):
    return x509.KeyUsage(digital_signature=True, key_cert_sign=ca, crl_sign=ca, key_agreement=not ca,
                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                         encipher_only=False, decipher_only=False)


def new_ca(label: str) -> tuple[str, str]:
    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"VPNix Create CA {label}")])
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(_now() - dt.timedelta(minutes=5))
         .not_valid_after(_now() + dt.timedelta(days=CA_DAYS))
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
         .add_extension(_ku(True), critical=True).sign(k, hashes.SHA256()))
    return _cert_pem(c), _key_pem(k)


def issue(ca_cert: str, ca_key: str, cn: str, server: bool) -> tuple[str, str]:
    ca = x509.load_pem_x509_certificate(ca_cert.encode())
    cak = serialization.load_pem_private_key(ca_key.encode(), None)
    k = ec.generate_private_key(ec.SECP256R1())
    eku = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
    c = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(ca.subject).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(_now() - dt.timedelta(minutes=5))
         .not_valid_after(_now() + dt.timedelta(days=SERVER_DAYS if server else CLIENT_DAYS))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(_ku(False), critical=True).add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
         .sign(cak, hashes.SHA256()))
    return _cert_pem(c), _key_pem(k)


def crl(ca_cert: str, ca_key: str, revoked_serials: list[int]) -> str:
    ca = x509.load_pem_x509_certificate(ca_cert.encode())
    cak = serialization.load_pem_private_key(ca_key.encode(), None)
    b = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject).last_update(_now())
         .next_update(_now() + dt.timedelta(days=3650)))
    for s in revoked_serials:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(s).revocation_date(_now()).build())
    return b.sign(cak, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def info(cert_pem: str) -> dict:
    c = x509.load_pem_x509_certificate(cert_pem.encode())
    return {"cn": c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "serial": c.serial_number,
            "not_after": c.not_valid_after_utc,
            "fingerprint": base64.b64encode(hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).digest()).decode()}


def new_cn() -> str:
    return "c" + secrets.token_hex(12)  # random, no personal data in certificates


def tls_crypt_key() -> str:
    h = os.urandom(256).hex()
    return "-----BEGIN OpenVPN Static key V1-----\n" + "\n".join(h[i:i + 32] for i in range(0, len(h), 32)) + \
           "\n-----END OpenVPN Static key V1-----\n"
