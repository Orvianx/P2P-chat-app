"""
crypto.py — Cryptographic primitives + Network-info helpers for P2P Secure Chat
=========================================================
Handles:
  • RSA-2048 key generation and serialization
  • RSA OAEP encryption/decryption (for AES key exchange)
  • Fernet (AES-128-CBC + HMAC-SHA256) symmetric encryption

Only deps: Python standard library + `cryptography` package.
"""

import os
import socket
import urllib.request
import urllib.error
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet


# ─────────────────────────────────────────────
# RSA Key Generation
# ─────────────────────────────────────────────

def generate_rsa_keypair():
    """
    Generate a fresh RSA-2048 private/public key pair at runtime.
    Keys are ephemeral — they are never saved to disk.

    Returns:
        (private_key, public_key) — cryptography library objects
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,   # Standard safe exponent (Fermat F4)
        key_size=2048,           # 2048-bit key = ~112 bits of security
    )
    public_key = private_key.public_key()
    return private_key, public_key


# ─────────────────────────────────────────────
# RSA Key Serialization (wire format)
# ─────────────────────────────────────────────

def serialize_public_key(public_key) -> bytes:
    """
    Serialize a public key to PEM format for transmission over the socket.

    Returns:
        bytes — PEM-encoded public key (safe to send over the wire)
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_data: bytes):
    """
    Deserialize a PEM-encoded public key received from the remote peer.

    Args:
        pem_data: raw bytes received from socket

    Returns:
        RSAPublicKey object
    """
    return serialization.load_pem_public_key(pem_data)


# ─────────────────────────────────────────────
# RSA Encryption / Decryption (for AES key exchange)
# ─────────────────────────────────────────────

def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    """
    Encrypt `plaintext` using the remote peer's RSA public key.
    Uses OAEP padding with SHA-256 — semantically secure, no padding oracle.

    Used to securely deliver the AES session key to the peer.

    Args:
        public_key: RSAPublicKey (peer's)
        plaintext:  raw bytes to encrypt (e.g. a Fernet key, 32 bytes)

    Returns:
        ciphertext bytes (length == key size in bytes, i.e. 256 for RSA-2048)
    """
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """
    Decrypt `ciphertext` using our own RSA private key.
    Recovers the AES session key sent by the remote peer.

    Args:
        private_key: RSAPrivateKey (ours)
        ciphertext:  bytes received from socket

    Returns:
        plaintext bytes (the AES session key)
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ─────────────────────────────────────────────
# AES Session Key (Fernet)
# ─────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """
    Generate a fresh 32-byte random Fernet key.
    Fernet = AES-128-CBC + HMAC-SHA256 with a random IV per message.

    Returns:
        bytes — URL-safe base64-encoded key (44 bytes encoded, 32 bytes raw)
    """
    return Fernet.generate_key()


def aes_encrypt(fernet_key: bytes, plaintext: str) -> bytes:
    """
    Encrypt a UTF-8 message string using the shared Fernet (AES) key.
    Each call produces a unique ciphertext (random IV embedded in token).

    Args:
        fernet_key: shared session key bytes
        plaintext:  message string from user

    Returns:
        Fernet token bytes (safe to send over socket)
    """
    f = Fernet(fernet_key)
    return f.encrypt(plaintext.encode("utf-8"))


def aes_decrypt(fernet_key: bytes, token: bytes) -> str:
    """
    Decrypt a Fernet token using the shared session key.
    Also verifies HMAC integrity — raises InvalidToken if tampered.

    Args:
        fernet_key: shared session key bytes
        token:      ciphertext bytes received from socket

    Returns:
        Decrypted message as a UTF-8 string
    """
    f = Fernet(fernet_key)
    return f.decrypt(token).decode("utf-8")


# ─────────────────────────────────────────────
# Network Information Helpers
# ─────────────────────────────────────────────

def get_local_ip() -> str:
    """
    Determine the machine's primary LAN IP address by opening a UDP
    socket toward a public address (no data is actually sent).
    Falls back to '127.0.0.1' if the machine has no network.

    Returns:
        String like '192.168.1.42'
    """
    try:
        # Using 8.8.8.8:80 as a target never actually sends a packet;
        # it just lets the OS pick the outgoing interface and its IP.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def get_public_ip(timeout: int = 5) -> str:
    """
    Fetch the machine's public (WAN) IP address by querying a plain-text
    HTTP endpoint. Tries three providers in order so that a single
    service being down doesn't break startup.

    Providers used (all return a bare IP string, no JSON):
        1. https://api.ipify.org
        2. https://ifconfig.me/ip
        3. https://icanhazip.com

    Args:
        timeout: seconds before each request is abandoned

    Returns:
        Public IP string, or 'unavailable' if all providers fail
        (e.g. offline machine or restrictive firewall).
    """
    providers = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    for url in providers:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "p2p-secure-chat/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ip = resp.read().decode().strip()
                # Basic sanity check — must look like an IPv4 address
                parts = ip.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    return ip
        except Exception:
            continue   # try the next provider
    return "unavailable"
