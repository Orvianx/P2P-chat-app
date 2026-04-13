"""
voice.py — Encrypted P2P VoIP Engine
======================================
Implements a complete real-time voice call system layered on top of the
existing P2P chat infrastructure.

Architecture
------------
  Signaling  : existing encrypted TCP channel  (call_request / accept / reject / end)
  Audio data : direct UDP sockets              (no relay, no STUN/TURN)

Call flow
---------
  Caller                                  Callee
  ──────                                  ──────
  /call
  → TCP: { "type": "call_request",
            "udp_port": <N> }
                                          📞  Incoming call from peer
                                          /accept  or  /reject
                                          → TCP: { "type": "call_accept",
                                                    "udp_port": <M> }
  UDP streams open (both directions)
  ── full-duplex audio ──────────────────────────────
  /hangup
  → TCP: { "type": "call_end" }
                                          streams close

UDP packet format (JSON)
------------------------
  { "type": "audio_stream", "data": "<base64 Fernet token>" }

Audio parameters
----------------
  Sample rate  : 44 100 Hz
  Channels     : 1  (mono)
  Frame size   : 1 024 samples  (~23 ms per frame)
  dtype        : float32

Encryption
----------
  Reuses the shared AES (Fernet) session key established during the TCP
  handshake — no extra key exchange needed.

Constraints
-----------
  ✓ Direct UDP peer-to-peer
  ✗ No NAT traversal / STUN / TURN
  ✗ No relay servers
  ✓ Works on LAN or Internet with port forwarding
"""

import base64
import json
import queue
import socket
import struct
import threading
import time
from enum import Enum, auto
from typing import Optional

import numpy as np

from cryptography.fernet import Fernet, InvalidToken

# ── Lazy sounddevice import so the module loads even if PortAudio is absent ──
try:
    import sounddevice as sd
    _SD_AVAILABLE = True
except (ImportError, OSError):
    _SD_AVAILABLE = False

# ── ANSI colours ──────────────────────────────────────────────────────────────
_G = "\033[92m"   # green
_C = "\033[96m"   # cyan
_Y = "\033[93m"   # yellow
_R = "\033[91m"   # red
_B = "\033[1m"    # bold
_D = "\033[2m"    # dim
_X = "\033[0m"    # reset
_M = "\033[95m"   # magenta

# ── Audio parameters ──────────────────────────────────────────────────────────
SAMPLE_RATE  = 44_100          # Hz
CHANNELS     = 1               # mono
FRAME_SIZE   = 1_024           # samples per frame  (~23 ms)
DTYPE        = "float32"       # 4 bytes/sample → 4 096 bytes raw per frame

# ── Network parameters ────────────────────────────────────────────────────────
UDP_TIMEOUT   = 2.0            # seconds; socket read blocks this long max
JITTER_MAXQ   = 30             # max queued frames before we drop old ones
UDP_PORT_BASE = 5100           # default UDP port (overridden by auto-binding)
UDP_RECV_BUF  = 131_072        # 128 KiB receive buffer


# ══════════════════════════════════════════════════════════════════════════════
# Call State Machine
# ══════════════════════════════════════════════════════════════════════════════

class CallState(Enum):
    IDLE     = auto()
    RINGING  = auto()   # outbound call placed, waiting for answer
    INCOMING = auto()   # inbound call received, waiting for our answer
    IN_CALL  = auto()


# ══════════════════════════════════════════════════════════════════════════════
# VoIPEngine
# ══════════════════════════════════════════════════════════════════════════════

class VoIPEngine:
    """
    Manages the full lifecycle of a VoIP call for one chat session.

    Parameters
    ----------
    tcp_sock  : the connected TCP socket shared with the chat session
    aes_key   : the shared Fernet session key (bytes)
    send_frame: the framing function from common.py  (sock, data) → None
    """

    def __init__(self, tcp_sock, aes_key: bytes, send_frame_fn):
        self._tcp         = tcp_sock
        self._aes         = aes_key
        self._fernet      = Fernet(aes_key)
        self._send_frame  = send_frame_fn

        self.state        = CallState.IDLE
        self._peer_udp_ip : Optional[str]  = None
        self._peer_udp_port: Optional[int] = None
        self._our_udp_port : Optional[int] = None

        self._udp_sock    : Optional[socket.socket]  = None
        self._play_q      : queue.Queue               = queue.Queue(maxsize=JITTER_MAXQ)
        self._call_stop   : threading.Event           = threading.Event()

        self._send_thread : Optional[threading.Thread] = None
        self._recv_thread : Optional[threading.Thread] = None

    # ── Public command handlers (called by the chat send_loop) ────────────────

    def cmd_call(self) -> None:
        """User typed /call — initiate an outbound call."""
        if self.state != CallState.IDLE:
            print(f"{_Y}  [!] Already in a call or waiting. Use /hangup first.{_X}")
            return
        if not _SD_AVAILABLE:
            print(f"{_R}  [!] sounddevice is not available. Install it: pip install sounddevice{_X}")
            return

        port = self._bind_udp()
        if port is None:
            return

        self.state = CallState.RINGING
        self._our_udp_port = port
        self._signal({"type": "call_request", "udp_port": port})
        print(f"\n{_M}{_B}  📞 Calling peer… (waiting for answer){_X}\n")

    def cmd_accept(self) -> None:
        """User typed /accept — accept an incoming call."""
        if self.state != CallState.INCOMING:
            print(f"{_Y}  [!] No incoming call to accept.{_X}")
            return
        if not _SD_AVAILABLE:
            print(f"{_R}  [!] sounddevice not available. Cannot accept call.{_X}")
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
        print(f"\n{_G}{_B}  ✅ Call accepted. Connected!{_X}")
        self._start_audio_threads()
        self._print_call_ui()

    def cmd_reject(self) -> None:
        """User typed /reject — decline an incoming call."""
        if self.state != CallState.INCOMING:
            print(f"{_Y}  [!] No incoming call to reject.{_X}")
            return
        self._signal({"type": "call_reject"})
        self.state = CallState.IDLE
        self._cleanup_udp()
        print(f"  {_Y}[✗] Call rejected.{_X}")

    def cmd_hangup(self) -> None:
        """User typed /hangup — end the current call."""
        if self.state == CallState.IDLE:
            print(f"{_Y}  [!] No active call to hang up.{_X}")
            return
        self._signal({"type": "call_end"})
        self._end_call(local=True)

    # ── Incoming TCP signal dispatcher (called by receive_loop) ───────────────

    def handle_signal(self, env: dict) -> None:
        """
        Dispatch an incoming call-control message received on the TCP channel.
        Called from common.receive_loop when type is a call_* type.
        """
        t = env.get("type")

        if t == "call_request":
            self._on_call_request(env)

        elif t == "call_accept":
            self._on_call_accept(env)

        elif t == "call_reject":
            self._on_call_reject()

        elif t == "call_end":
            self._on_call_end()

    # ── Internal signal helpers ───────────────────────────────────────────────

    def _signal(self, payload: dict) -> None:
        """Send a call-control JSON message over the TCP channel."""
        try:
            self._send_frame(self._tcp, json.dumps(payload).encode())
        except Exception as e:
            print(f"{_R}  [!] Failed to send call signal: {e}{_X}")

    # ── Incoming signal handlers ──────────────────────────────────────────────

    def _on_call_request(self, env: dict) -> None:
        if self.state != CallState.IDLE:
            # Already busy — auto-reject
            self._signal({"type": "call_reject"})
            return

        self._peer_udp_ip   = self._tcp.getpeername()[0]
        self._peer_udp_port = env.get("udp_port")
        self.state = CallState.INCOMING

        print(f"\n{_M}{_B}  📞 Incoming voice call from peer!{_X}")
        print(f"{_C}     Type {_B}/accept{_X}{_C} to answer or {_B}/reject{_X}{_C} to decline.{_X}\n")
        # Re-print input prompt so the UI stays usable
        print(f"{_D}[voice] You:{_X} ", end="", flush=True)

    def _on_call_accept(self, env: dict) -> None:
        if self.state != CallState.RINGING:
            return
        self._peer_udp_ip   = self._tcp.getpeername()[0]
        self._peer_udp_port = env.get("udp_port")
        self.state = CallState.IN_CALL
        print(f"\n{_G}{_B}  ✅ Peer answered! Call connected.{_X}")
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

    # ── UDP socket management ─────────────────────────────────────────────────

    def _bind_udp(self) -> Optional[int]:
        """
        Bind a UDP socket on an available port.
        Returns the bound port number, or None on failure.
        """
        try:
            self._cleanup_udp()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_RECV_BUF)
            sock.bind(("0.0.0.0", 0))   # OS chooses a free port
            sock.settimeout(UDP_TIMEOUT)
            self._udp_sock = sock
            port = sock.getsockname()[1]
            print(f"{_D}  [*] UDP socket bound on port {port}.{_X}")
            return port
        except OSError as e:
            print(f"{_R}  [!] Could not bind UDP socket: {e}{_X}")
            return None

    def _cleanup_udp(self) -> None:
        if self._udp_sock is not None:
            try:
                self._udp_sock.close()
            except Exception:
                pass
            self._udp_sock = None

    # ── Audio thread management ───────────────────────────────────────────────

    def _start_audio_threads(self) -> None:
        """Launch the send (capture+transmit) and receive (recv+play) threads."""
        self._call_stop.clear()
        # Drain the jitter buffer
        while not self._play_q.empty():
            try:
                self._play_q.get_nowait()
            except queue.Empty:
                break

        self._send_thread = threading.Thread(
            target=self._audio_send_loop, daemon=True, name="voip-send"
        )
        self._recv_thread = threading.Thread(
            target=self._audio_recv_loop, daemon=True, name="voip-recv"
        )
        self._send_thread.start()
        self._recv_thread.start()

    def _stop_audio_threads(self) -> None:
        self._call_stop.set()
        if self._send_thread:
            self._send_thread.join(timeout=3)
        if self._recv_thread:
            self._recv_thread.join(timeout=3)
        self._send_thread = None
        self._recv_thread = None

    # ── Audio capture + transmit thread ──────────────────────────────────────

    def _audio_send_loop(self) -> None:
        """
        Continuously:
          1. Capture FRAME_SIZE samples from the microphone.
          2. Encrypt the raw float32 bytes with Fernet.
          3. Wrap in a JSON packet.
          4. Send over UDP to the peer.

        Uses sounddevice.RawInputStream for low-latency, non-blocking capture.
        Falls back gracefully if the microphone is unavailable.
        """
        if not _SD_AVAILABLE:
            return

        try:
            stream = sd.InputStream(
                samplerate=SAMPLE_RATE,
                channels=CHANNELS,
                dtype=DTYPE,
                blocksize=FRAME_SIZE,
            )
            stream.start()
        except Exception as e:
            print(f"\n{_R}  [!] Microphone error: {e}{_X}")
            print(f"{_Y}  [!] Audio capture disabled. You can still hear peer audio.{_X}")
            return

        print(f"{_D}  [voip] Microphone capture started.{_X}")

        try:
            while not self._call_stop.is_set():
                # Read one frame (blocking up to 200 ms)
                try:
                    audio_data, overflowed = stream.read(FRAME_SIZE)
                except Exception:
                    break

                if overflowed:
                    pass   # minor buffer issue — just continue

                # audio_data is a numpy array shape (FRAME_SIZE, CHANNELS)
                raw_bytes = np.asarray(audio_data, dtype=np.float32).tobytes()

                # Encrypt
                try:
                    enc = self._fernet.encrypt(raw_bytes)
                except Exception:
                    continue

                # Build JSON packet
                pkt = json.dumps({
                    "type": "audio_stream",
                    "data": base64.b64encode(enc).decode("ascii"),
                }).encode("ascii")

                # Send over UDP
                try:
                    if self._udp_sock and self._peer_udp_ip and self._peer_udp_port:
                        self._udp_sock.sendto(pkt, (self._peer_udp_ip, self._peer_udp_port))
                except OSError:
                    break   # socket was closed

        finally:
            try:
                stream.stop()
                stream.close()
            except Exception:
                pass
            print(f"{_D}  [voip] Microphone capture stopped.{_X}")

    # ── Audio receive + playback thread ──────────────────────────────────────

    def _audio_recv_loop(self) -> None:
        """
        Continuously:
          1. Receive a UDP packet from peer.
          2. Decrypt the Fernet token.
          3. Push decoded float32 samples into the jitter buffer queue.

        A separate sounddevice OutputStream pulls from the queue and plays.
        """
        if not _SD_AVAILABLE:
            return

        # ── Playback stream using a callback ─────────────────────────────────
        silence = np.zeros((FRAME_SIZE, CHANNELS), dtype=np.float32)

        def _play_callback(outdata, frames, time_info, status):
            """Called by PortAudio on the audio thread to fill the output buffer."""
            try:
                frame = self._play_q.get_nowait()
                outdata[:] = frame.reshape(frames, CHANNELS)
            except queue.Empty:
                outdata[:] = silence   # play silence if jitter buffer is empty

        try:
            out_stream = sd.OutputStream(
                samplerate=SAMPLE_RATE,
                channels=CHANNELS,
                dtype=DTYPE,
                blocksize=FRAME_SIZE,
                callback=_play_callback,
            )
            out_stream.start()
        except Exception as e:
            print(f"\n{_R}  [!] Audio output error: {e}{_X}")
            return

        print(f"{_D}  [voip] Audio playback started.{_X}")

        try:
            while not self._call_stop.is_set():
                if self._udp_sock is None:
                    break
                try:
                    raw_pkt, addr = self._udp_sock.recvfrom(65_535)
                except socket.timeout:
                    continue    # normal — no packet arrived in this window
                except OSError:
                    break       # socket closed

                # Parse JSON envelope
                try:
                    env = json.loads(raw_pkt.decode("ascii"))
                    if env.get("type") != "audio_stream":
                        continue
                    enc = base64.b64decode(env["data"])
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue    # malformed packet — discard

                # Decrypt
                try:
                    dec_bytes = self._fernet.decrypt(enc)
                except InvalidToken:
                    continue    # tampered / wrong key — discard silently

                # Reconstruct numpy array and push to jitter buffer
                try:
                    arr = np.frombuffer(dec_bytes, dtype=np.float32).copy()
                    if arr.size != FRAME_SIZE:
                        continue   # wrong size — skip

                    # Drop oldest frame if buffer is full (avoids growing latency)
                    if self._play_q.full():
                        try:
                            self._play_q.get_nowait()
                        except queue.Empty:
                            pass
                    self._play_q.put_nowait(arr)

                except Exception:
                    continue

        finally:
            try:
                out_stream.stop()
                out_stream.close()
            except Exception:
                pass
            print(f"{_D}  [voip] Audio playback stopped.{_X}")

    # ── Teardown ──────────────────────────────────────────────────────────────

    def _end_call(self, local: bool) -> None:
        """Stop audio threads, close UDP socket, reset state."""
        was_in_call = (self.state == CallState.IN_CALL)
        self.state  = CallState.IDLE

        self._stop_audio_threads()
        self._cleanup_udp()
        self._peer_udp_ip   = None
        self._peer_udp_port = None
        self._our_udp_port  = None

        if was_in_call:
            action = "ended" if local else "ended by peer"
            print(f"\n{_Y}  📵 Call {action}.{_X}")

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _print_call_ui() -> None:
        print(f"\n{_D}  ┌─────────────────────────────────┐")
        print(f"  │  🔊 Voice call active            │")
        print(f"  │  Type {_X}/hangup{_D} to end the call   │")
        print(f"  └─────────────────────────────────┘{_X}\n")

    @property
    def in_call(self) -> bool:
        return self.state == CallState.IN_CALL

    @property
    def is_idle(self) -> bool:
        return self.state == CallState.IDLE


# ══════════════════════════════════════════════════════════════════════════════
# Standalone test helpers (not used in production)
# ══════════════════════════════════════════════════════════════════════════════

def _selftest_audio_pipeline():
    """Verify encrypt→UDP-packet→decrypt round-trip without real hardware."""
    from cryptography.fernet import Fernet
    key  = Fernet.generate_key()
    fen  = Fernet(key)
    frame = np.random.uniform(-0.3, 0.3, FRAME_SIZE).astype(np.float32)

    # Simulate send side
    raw  = frame.tobytes()
    enc  = fen.encrypt(raw)
    pkt  = json.dumps({
        "type": "audio_stream",
        "data": base64.b64encode(enc).decode("ascii"),
    }).encode("ascii")

    # Simulate receive side
    env  = json.loads(pkt.decode("ascii"))
    dec  = fen.decrypt(base64.b64decode(env["data"]))
    arr  = np.frombuffer(dec, dtype=np.float32)

    assert np.allclose(arr, frame), "Audio pipeline round-trip failed"
    assert len(pkt) < 65_535, "UDP packet too large"
    return True
