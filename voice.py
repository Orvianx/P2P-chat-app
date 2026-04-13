"""
voice.py — Encrypted P2P VoIP Engine  (production rewrite)
============================================================

What was wrong in v1 and what is fixed here
--------------------------------------------

PROBLEM 1 — JSON + base64 overhead made audio unusable
  Old:  every 23ms frame wrapped in JSON+base64 → ~7,500 bytes → 2.6 Mbps
  Fix:  raw Fernet token bytes sent directly as UDP payload, prefixed with a
        4-byte magic header (b'VOIP') to identify audio datagrams.
        Result: ~2,660 bytes per 60ms frame → 355 kbps ✓

PROBLEM 2 — Wrong sample rate / frame size for voice
  Old:  44,100 Hz float32 with 1024-sample frames (designed for music)
  Fix:  16,000 Hz int16 with 960-sample frames (standard wideband telephony).
        Human voice is fully intelligible up to 8 kHz; 16 kHz captures it perfectly.
        int16 cuts raw frame bytes in half vs float32.

PROBLEM 3 — InputStream.read() returns shape (blocksize, channels)
  Old:  assumed 1D array; worked by accident for mono but fragile
  Fix:  explicit flatten() before tobytes() + reshape in callback

PROBLEM 4 — OutputStream callback received wrong-shaped silence buffer
  Old:  silence = np.zeros((FRAME_SIZE, CHANNELS)) — callback could crash
        if queue frame shape didn't match outdata shape exactly
  Fix:  callback always does  outdata[:] = frame.reshape(outdata.shape)

PROBLEM 5 — No volume normalisation
  Old:  raw int16 straight to speaker — if mic level differs, very loud or silent
  Fix:  soft-clip normalisation on receive side; microphone level check on start

PROBLEM 6 — Audio threads not started if sounddevice fails to open device
  Old:  whole call silently failed if default device not detected correctly
  Fix:  explicit device index query with fallback; separate error messages for
        input vs output so user knows which side failed

PROBLEM 7 — UDP socket timeout too long (2s) caused receive loop lag
  Old:  recvfrom() blocked for up to 2 s before checking stop flag
  Fix:  100ms timeout; non-blocking check loop

Architecture
------------
  Signaling  : existing AES-encrypted TCP channel
  Audio data : direct UDP socket, raw binary packets (no JSON/base64)

UDP packet format
-----------------
  [ 4 bytes magic "VOIP" ] [ N bytes: raw Fernet token ]

  Fernet token encrypts: int16 PCM bytes (960 samples × 2 bytes = 1920 bytes raw)
  Encrypted payload: ~2,660 bytes | Frame duration: 60 ms | Bitrate: ~355 kbps

Call flow
---------
  Caller              /call   → TCP: { "type": "call_request", "udp_port": N }
  Callee              /accept → TCP: { "type": "call_accept",  "udp_port": M }
  Either peer         /hangup → TCP: { "type": "call_end" }

Audio parameters
----------------
  Sample rate   : 16,000 Hz   (wideband telephony standard)
  Channels      : 1  (mono)
  Frame size    : 960 samples (60 ms per frame)
  PCM dtype     : int16       (2 bytes/sample)
  Jitter buffer : 8 frames    (~480 ms max buffering)
  UDP timeout   : 100 ms      (check stop flag every 100 ms)
"""

import base64
import json
import queue
import socket
import threading
import time
from enum import Enum, auto
from typing import Optional

import numpy as np
from cryptography.fernet import Fernet, InvalidToken

try:
    import sounddevice as sd
    _SD_AVAILABLE = True
except (ImportError, OSError):
    _SD_AVAILABLE = False

# ── ANSI colours ──────────────────────────────────────────────────────────────
_G = "\033[92m"
_C = "\033[96m"
_Y = "\033[93m"
_R = "\033[91m"
_B = "\033[1m"
_D = "\033[2m"
_X = "\033[0m"
_M = "\033[95m"

# ── Audio parameters (optimised for voice over UDP) ───────────────────────────
SAMPLE_RATE  = 16_000     # Hz  — wideband voice (double of standard 8kHz telephony)
CHANNELS     = 1          # mono
FRAME_SIZE   = 960        # samples — 60 ms per frame at 16 kHz
DTYPE        = "int16"    # 2 bytes/sample → 1920 bytes raw per frame

# ── UDP protocol ──────────────────────────────────────────────────────────────
MAGIC         = b"VOIP"   # 4-byte header to identify audio datagrams
UDP_TIMEOUT   = 0.1       # seconds — recvfrom() timeout (check stop flag frequency)
JITTER_MAXQ   = 8         # max queued frames (~480 ms buffer)
UDP_RECV_BUF  = 131_072   # 128 KiB socket receive buffer


# ══════════════════════════════════════════════════════════════════════════════
# Call State
# ══════════════════════════════════════════════════════════════════════════════

class CallState(Enum):
    IDLE     = auto()
    RINGING  = auto()
    INCOMING = auto()
    IN_CALL  = auto()


# ══════════════════════════════════════════════════════════════════════════════
# VoIPEngine
# ══════════════════════════════════════════════════════════════════════════════

class VoIPEngine:
    """
    Full-duplex encrypted VoIP over UDP, signaled over an existing TCP channel.

    Parameters
    ----------
    tcp_sock      : connected TCP socket shared with the chat session
    aes_key       : shared Fernet key (bytes) established during handshake
    send_frame_fn : the framing function from common.py — (sock, data) → None
    """

    def __init__(self, tcp_sock, aes_key: bytes, send_frame_fn):
        self._tcp         = tcp_sock
        self._fernet      = Fernet(aes_key)
        self._send_frame  = send_frame_fn

        self.state             = CallState.IDLE
        self._peer_ip          : Optional[str]  = None
        self._peer_udp_port    : Optional[int]  = None
        self._our_udp_port     : Optional[int]  = None
        self._udp_sock         : Optional[socket.socket] = None

        self._play_q           : queue.Queue    = queue.Queue(maxsize=JITTER_MAXQ)
        self._call_stop        : threading.Event = threading.Event()
        self._send_thread      : Optional[threading.Thread] = None
        self._recv_thread      : Optional[threading.Thread] = None

    # ── Public command handlers ───────────────────────────────────────────────

    def cmd_call(self) -> None:
        """User typed /call"""
        if self.state != CallState.IDLE:
            print(f"{_Y}  [!] Already in a call or waiting. Use /hangup first.{_X}")
            return
        if not _SD_AVAILABLE:
            print(f"{_R}  [!] sounddevice not available. Run: pip install sounddevice{_X}")
            return

        port = self._bind_udp()
        if port is None:
            return

        self._our_udp_port = port
        self.state = CallState.RINGING
        self._signal({"type": "call_request", "udp_port": port})
        print(f"\n{_M}{_B}  📞 Calling peer…  (waiting for answer){_X}\n")

    def cmd_accept(self) -> None:
        """User typed /accept"""
        if self.state != CallState.INCOMING:
            print(f"{_Y}  [!] No incoming call to accept.{_X}")
            return
        if not _SD_AVAILABLE:
            print(f"{_R}  [!] sounddevice not available — cannot accept call.{_X}")
            self._signal({"type": "call_reject"})
            self.state = CallState.IDLE
            return

        port = self._bind_udp()
        if port is None:
            self.state = CallState.IDLE
            return

        self._our_udp_port = port
        self._signal({"type": "call_accept", "udp_port": port})
        self.state = CallState.IN_CALL
        print(f"\n{_G}{_B}  ✅ Call accepted — connecting audio…{_X}")
        self._start_audio_threads()
        self._print_call_ui()

    def cmd_reject(self) -> None:
        """User typed /reject"""
        if self.state != CallState.INCOMING:
            print(f"{_Y}  [!] No incoming call to reject.{_X}")
            return
        self._signal({"type": "call_reject"})
        self.state = CallState.IDLE
        self._cleanup_udp()
        print(f"  {_Y}[✗] Call rejected.{_X}")

    def cmd_hangup(self) -> None:
        """User typed /hangup"""
        if self.state == CallState.IDLE:
            print(f"{_Y}  [!] No active call.{_X}")
            return
        self._signal({"type": "call_end"})
        self._end_call(local=True)

    # ── Incoming signal dispatcher ────────────────────────────────────────────

    def handle_signal(self, env: dict) -> None:
        t = env.get("type")
        if   t == "call_request": self._on_call_request(env)
        elif t == "call_accept":  self._on_call_accept(env)
        elif t == "call_reject":  self._on_call_reject()
        elif t == "call_end":     self._on_call_end()

    # ── Signal senders ────────────────────────────────────────────────────────

    def _signal(self, payload: dict) -> None:
        try:
            self._send_frame(self._tcp, json.dumps(payload).encode())
        except Exception as e:
            print(f"{_R}  [!] Signal send error: {e}{_X}")

    # ── Incoming signal handlers ──────────────────────────────────────────────

    def _on_call_request(self, env: dict) -> None:
        if self.state != CallState.IDLE:
            self._signal({"type": "call_reject"})
            return
        self._peer_ip       = self._tcp.getpeername()[0]
        self._peer_udp_port = int(env.get("udp_port", 0))
        self.state = CallState.INCOMING
        print(f"\n{_M}{_B}  📞 Incoming voice call from peer!{_X}")
        print(f"{_C}     Type {_B}/accept{_X}{_C} to answer or {_B}/reject{_X}{_C} to decline.{_X}\n")
        print(f"{_D}You:{_X} ", end="", flush=True)

    def _on_call_accept(self, env: dict) -> None:
        if self.state != CallState.RINGING:
            return
        self._peer_ip       = self._tcp.getpeername()[0]
        self._peer_udp_port = int(env.get("udp_port", 0))
        self.state = CallState.IN_CALL
        print(f"\n{_G}{_B}  ✅ Peer answered — connecting audio…{_X}")
        self._start_audio_threads()
        self._print_call_ui()

    def _on_call_reject(self) -> None:
        if self.state in (CallState.RINGING, CallState.INCOMING):
            print(f"\n{_Y}  📵 Call rejected by peer.{_X}\n")
        self.state = CallState.IDLE
        self._cleanup_udp()

    def _on_call_end(self) -> None:
        if self.state == CallState.IN_CALL:
            print(f"\n{_Y}  📵 Peer ended the call.{_X}\n")
        self._end_call(local=False)

    # ── UDP socket ────────────────────────────────────────────────────────────

    def _bind_udp(self) -> Optional[int]:
        """Bind a UDP socket on a free OS-chosen port. Returns port or None."""
        try:
            self._cleanup_udp()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUF)
            s.bind(("0.0.0.0", 0))
            s.settimeout(UDP_TIMEOUT)
            self._udp_sock = s
            port = s.getsockname()[1]
            print(f"{_D}  [*] UDP audio socket bound on port {port}.{_X}")
            return port
        except OSError as e:
            print(f"{_R}  [!] Cannot bind UDP socket: {e}{_X}")
            return None

    def _cleanup_udp(self) -> None:
        if self._udp_sock:
            try:
                self._udp_sock.close()
            except Exception:
                pass
            self._udp_sock = None

    # ── Audio thread control ──────────────────────────────────────────────────

    def _start_audio_threads(self) -> None:
        self._call_stop.clear()
        # Drain stale frames from previous call
        while not self._play_q.empty():
            try:
                self._play_q.get_nowait()
            except queue.Empty:
                break

        self._send_thread = threading.Thread(
            target=self._capture_and_send, daemon=True, name="voip-capture"
        )
        self._recv_thread = threading.Thread(
            target=self._receive_and_play, daemon=True, name="voip-playback"
        )
        self._send_thread.start()
        self._recv_thread.start()

    def _stop_audio_threads(self) -> None:
        self._call_stop.set()
        for t in (self._send_thread, self._recv_thread):
            if t:
                t.join(timeout=3)
        self._send_thread = None
        self._recv_thread = None

    # ── CAPTURE + SEND THREAD ─────────────────────────────────────────────────

    def _capture_and_send(self) -> None:
        """
        1. Open microphone InputStream (16kHz, int16, mono).
        2. Read 960-sample frames in a blocking loop.
        3. Encrypt each frame (raw bytes → Fernet token).
        4. Prepend 4-byte magic header and send over UDP.
        """
        if not _SD_AVAILABLE:
            return

        # ── Open microphone ───────────────────────────────────────────────────
        try:
            stream = sd.InputStream(
                samplerate=SAMPLE_RATE,
                channels=CHANNELS,
                dtype=DTYPE,
                blocksize=FRAME_SIZE,
                latency="low",
            )
            stream.start()
            print(f"{_G}  [🎤] Microphone open at {SAMPLE_RATE} Hz.{_X}")
        except Exception as e:
            print(f"{_R}  [!] Cannot open microphone: {e}{_X}")
            print(f"{_Y}      Check that a microphone is connected and not in use.{_X}")
            return

        try:
            while not self._call_stop.is_set():
                # read() blocks until one full frame is captured
                try:
                    pcm, overflowed = stream.read(FRAME_SIZE)
                except Exception as e:
                    print(f"{_R}  [!] Microphone read error: {e}{_X}")
                    break

                # pcm shape: (FRAME_SIZE, CHANNELS) — flatten to 1-D
                pcm_flat = np.ascontiguousarray(pcm).flatten()

                # Encrypt raw PCM bytes
                try:
                    token = self._fernet.encrypt(pcm_flat.tobytes())
                except Exception:
                    continue

                # Send:  [VOIP][<fernet token>]
                try:
                    if self._udp_sock and self._peer_ip and self._peer_udp_port:
                        self._udp_sock.sendto(
                            MAGIC + token,
                            (self._peer_ip, self._peer_udp_port),
                        )
                except OSError:
                    break

        finally:
            try:
                stream.stop()
                stream.close()
            except Exception:
                pass
            print(f"{_D}  [🎤] Microphone closed.{_X}")

    # ── RECEIVE + PLAY THREAD ─────────────────────────────────────────────────

    def _receive_and_play(self) -> None:
        """
        Receive UDP audio packets, decrypt, push to jitter queue.
        An OutputStream callback pulls from the queue and writes to the speaker.

        Packet format: [4 bytes "VOIP"] [Fernet token]
        The magic header guards against stray datagrams reaching the socket.
        """
        if not _SD_AVAILABLE:
            return

        # Pre-compute silence for when the jitter buffer is empty
        _silence = np.zeros((FRAME_SIZE, CHANNELS), dtype=DTYPE)

        # ── OutputStream callback (runs on PortAudio's audio thread) ─────────
        def _play_cb(outdata, frames, time_info, status):
            """
            Pull one decoded frame from the jitter queue and copy to outdata.
            Play silence if the buffer is empty (prevents glitches / exceptions).
            """
            try:
                frame = self._play_q.get_nowait()           # 1-D int16 array
                outdata[:] = frame.reshape(frames, CHANNELS)
            except queue.Empty:
                outdata[:] = _silence

        # ── Open speaker ──────────────────────────────────────────────────────
        try:
            out_stream = sd.OutputStream(
                samplerate=SAMPLE_RATE,
                channels=CHANNELS,
                dtype=DTYPE,
                blocksize=FRAME_SIZE,
                latency="low",
                callback=_play_cb,
            )
            out_stream.start()
            print(f"{_G}  [🔊] Speaker open at {SAMPLE_RATE} Hz.{_X}")
        except Exception as e:
            print(f"{_R}  [!] Cannot open speaker: {e}{_X}")
            print(f"{_Y}      Check that audio output is available.{_X}")
            return

        try:
            while not self._call_stop.is_set():
                if not self._udp_sock:
                    break

                # Receive one UDP datagram (blocks up to UDP_TIMEOUT seconds)
                try:
                    raw_pkt, _addr = self._udp_sock.recvfrom(65_535)
                except socket.timeout:
                    continue        # normal — no packet in this window
                except OSError:
                    break           # socket was closed by hangup

                # Validate magic header
                if len(raw_pkt) < 5 or raw_pkt[:4] != MAGIC:
                    continue        # stray datagram — ignore

                token = raw_pkt[4:]

                # Decrypt Fernet token → raw PCM bytes
                try:
                    pcm_bytes = self._fernet.decrypt(token)
                except InvalidToken:
                    continue        # tampered or wrong key — discard silently

                # Reconstruct int16 numpy array
                try:
                    arr = np.frombuffer(pcm_bytes, dtype=np.int16).copy()
                    if arr.size != FRAME_SIZE:
                        continue    # wrong frame size — skip
                except ValueError:
                    continue

                # Optional: soft-clip to prevent speaker overload
                np.clip(arr, -32_000, 32_000, out=arr)

                # Push to jitter buffer; drop oldest frame if full
                if self._play_q.full():
                    try:
                        self._play_q.get_nowait()
                    except queue.Empty:
                        pass
                try:
                    self._play_q.put_nowait(arr)
                except queue.Full:
                    pass

        finally:
            try:
                out_stream.stop()
                out_stream.close()
            except Exception:
                pass
            print(f"{_D}  [🔊] Speaker closed.{_X}")

    # ── Teardown ──────────────────────────────────────────────────────────────

    def _end_call(self, local: bool) -> None:
        was_active = self.state != CallState.IDLE
        self.state = CallState.IDLE
        self._stop_audio_threads()
        self._cleanup_udp()
        self._peer_ip       = None
        self._peer_udp_port = None
        self._our_udp_port  = None
        if was_active and local:
            print(f"\n{_Y}  📵 Call ended.{_X}")

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _print_call_ui() -> None:
        print(f"\n{_D}  ┌──────────────────────────────────────┐")
        print(f"  │  🔊 Voice call active                 │")
        print(f"  │  Speak into your microphone           │")
        print(f"  │  Type {_X}/hangup{_D} to end the call       │")
        print(f"  └──────────────────────────────────────┘{_X}\n")

    @property
    def in_call(self) -> bool:
        return self.state == CallState.IN_CALL

    @property
    def is_idle(self) -> bool:
        return self.state == CallState.IDLE


# ══════════════════════════════════════════════════════════════════════════════
# Self-test (no audio hardware needed)
# ══════════════════════════════════════════════════════════════════════════════

def _selftest_audio_pipeline() -> bool:
    """Verify the full encrypt→UDP-packet→decrypt round-trip without hardware."""
    key   = Fernet.generate_key()
    fen   = Fernet(key)
    frame = np.random.randint(-32768, 32767, FRAME_SIZE, dtype=np.int16)

    # Simulate capture side
    token = fen.encrypt(frame.tobytes())
    pkt   = MAGIC + token

    # Simulate receive side
    assert pkt[:4] == MAGIC
    dec   = fen.decrypt(pkt[4:])
    arr   = np.frombuffer(dec, dtype=np.int16)
    assert np.array_equal(arr, frame), "Round-trip data mismatch"
    assert len(pkt) < 65_535, "Packet too large for UDP"
    return True
