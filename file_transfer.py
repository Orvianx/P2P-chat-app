"""
file_transfer.py — Encrypted Chunked File Transfer
====================================================
Sends and receives files over an existing TCP connection using the same
framed-socket protocol as the chat layer.

Wire protocol per chunk:

  JSON envelope (framed):
  {
    "type":        "file",
    "filename":    "report.pdf",
    "size":        204800,          # total bytes of original file
    "chunk_count": 4,               # total number of chunks
    "chunk_index": 0,               # 0-based index
    "data":        "<base64 Fernet token>"
  }

  A final sentinel frame is sent after all chunks:
  { "type": "file_done", "filename": "report.pdf" }

Chunk size is 64 KiB (before encryption). Fernet tokens are base64-encoded
inside the JSON so the outer frame remains valid UTF-8.
"""

import json
import os
import base64
import struct

import crypto
import history

CHUNK_SIZE    = 64 * 1024           # 64 KiB raw chunk size
RECEIVED_DIR  = "received_files"


# ── Low-level framing (must match host.py / client.py) ───────────────────────

def _send_frame(sock, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_frame(sock) -> bytes:
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("Connection closed while reading frame header.")
        hdr += chunk
    n = struct.unpack(">I", hdr)[0]
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading frame body.")
        buf += chunk
    return buf


# ── Send side ─────────────────────────────────────────────────────────────────

def send_file(sock, aes_key: bytes, filepath: str) -> bool:
    """
    Read `filepath`, split into encrypted chunks, and stream over `sock`.

    Args:
        sock:     connected TCP socket
        aes_key:  shared Fernet key for this session
        filepath: path to the file to send

    Returns:
        True on success, False on error.
    """
    if not os.path.isfile(filepath):
        print(f"  [!] File not found: {filepath}")
        return False

    filename  = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)

    # Calculate chunk count up-front so the receiver knows when to stop
    chunk_count = max(1, (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE)

    print(f"  [→] Sending '{filename}'  ({file_size:,} bytes, {chunk_count} chunk(s))…")

    try:
        with open(filepath, "rb") as fh:
            for idx in range(chunk_count):
                raw_chunk = fh.read(CHUNK_SIZE)
                if not raw_chunk:
                    break

                # Encrypt the chunk; encode the Fernet token as base64 for JSON
                enc_chunk = crypto.aes_encrypt_bytes(aes_key, raw_chunk)
                b64_chunk = base64.b64encode(enc_chunk).decode("ascii")

                envelope = json.dumps({
                    "type":        "file",
                    "filename":    filename,
                    "size":        file_size,
                    "chunk_count": chunk_count,
                    "chunk_index": idx,
                    "data":        b64_chunk,
                }).encode("utf-8")

                _send_frame(sock, envelope)

                # Simple progress bar
                pct = int((idx + 1) / chunk_count * 100)
                bar = ("█" * (pct // 5)).ljust(20)
                print(f"\r  [{bar}] {pct:3d}%  chunk {idx+1}/{chunk_count}", end="", flush=True)

        # Send sentinel so the receiver knows all chunks arrived
        sentinel = json.dumps({"type": "file_done", "filename": filename}).encode()
        _send_frame(sock, sentinel)

        print(f"\n  [✓] '{filename}' sent successfully.")
        history.log_file_sent(filename, file_size)
        return True

    except Exception as e:
        print(f"\n  [✗] File send error: {e}")
        return False


# ── Receive side ──────────────────────────────────────────────────────────────

def receive_file(sock, aes_key: bytes, first_frame: dict) -> None:
    """
    Called by the receive loop when the first frame has type == "file".
    Reassembles all chunks into `received_files/<filename>`.

    Args:
        sock:        connected TCP socket
        aes_key:     shared Fernet key
        first_frame: the already-parsed first chunk envelope (dict)
    """
    os.makedirs(RECEIVED_DIR, exist_ok=True)

    filename    = first_frame["filename"]
    file_size   = first_frame["size"]
    chunk_count = first_frame["chunk_count"]
    save_path   = os.path.join(RECEIVED_DIR, filename)

    # Guard against path traversal
    if ".." in filename or filename.startswith("/"):
        print(f"\n  [!] Rejected suspicious filename: {filename}")
        return

    print(f"\n  [←] Receiving '{filename}'  ({file_size:,} bytes, {chunk_count} chunk(s))…")

    chunks: dict[int, bytes] = {}   # index → decrypted bytes

    # Process the first chunk we already have
    def _process(env: dict):
        idx  = env["chunk_index"]
        enc  = base64.b64decode(env["data"].encode("ascii"))
        try:
            chunks[idx] = crypto.aes_decrypt_bytes(aes_key, enc)
        except Exception as e:
            raise ValueError(f"Chunk {idx} decryption failed: {e}") from e

    _process(first_frame)

    # Read the remaining chunks + the sentinel
    received = 1
    while received < chunk_count:
        raw = _recv_frame(sock)
        env = json.loads(raw.decode("utf-8"))

        if env.get("type") == "file_done":
            break
        if env.get("type") == "file" and env.get("filename") == filename:
            _process(env)
            received += 1
            pct = int(received / chunk_count * 100)
            bar = ("█" * (pct // 5)).ljust(20)
            print(f"\r  [{bar}] {pct:3d}%  chunk {received}/{chunk_count}", end="", flush=True)

    # Wait for sentinel if we haven't seen it yet
    # (it may arrive right after the last chunk)
    # (already consumed above when type == "file_done")

    if len(chunks) != chunk_count:
        print(f"\n  [!] Incomplete transfer: got {len(chunks)}/{chunk_count} chunks.")
        return

    # Reassemble in index order and write to disk
    with open(save_path, "wb") as fh:
        for i in range(chunk_count):
            fh.write(chunks[i])

    actual_size = os.path.getsize(save_path)
    print(f"\n  [✓] Saved to '{save_path}'  ({actual_size:,} bytes).")
    history.log_file_received(filename, actual_size, save_path)
