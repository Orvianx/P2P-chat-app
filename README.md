# 🔒 P2P Secure Chat v2

A **pure peer-to-peer** secure terminal chat tool with file transfer and
local history — no server, no cloud, no relay of any kind.

---

## ⚠️ Pure P2P — No Server Involved

Both peers communicate directly over a **TCP socket**.
No central server, no message broker, no relay, no cloud service.

| Scenario | Works? | What to use |
|---|---|---|
| Same WiFi / LAN | ✅ | Local IP (`192.168.x.x`) |
| Internet (different networks) | ✅ | Public IP + router port forwarding |
| Both behind NAT, no port forwarding | ❌ | Not supported by design |

---

## 📦 Project Structure

```
p2p_secure_chat/
├── host.py           Listening peer
├── client.py         Connecting peer
├── crypto.py         RSA + AES cryptography + IP helpers
├── common.py         Shared framing, handshake, chat engine
├── file_transfer.py  Encrypted chunked file transfer
├── history.py        Local JSON chat history
├── chat.sh           SSH-style CLI wrapper
├── received_files/   Incoming files saved here (auto-created)
└── chat_history.json Local event log (auto-created)
```

---

## 🔐 Security Architecture

```
Peer A (host)                         Peer B (client)
──────────────────────────────────────────────────────
Generate RSA-2048 key pair            Generate RSA-2048 key pair

Send RSA public key ─────────────────────────────────►
                    ◄───────────────────── Send RSA public key

Generate AES session key
Encrypt AES key with B's RSA pub key
Send encrypted AES key ──────────────────────────────►
                              Decrypt with own RSA private key

══════════ All subsequent traffic: AES-Fernet encrypted ══════════
```

| Threat | Mitigation |
|---|---|
| Eavesdropping | AES-Fernet on every frame |
| AES key theft | Key sent only RSA-OAEP encrypted |
| Tampering | Fernet includes HMAC-SHA256 per message |
| IV reuse | Fernet generates a fresh random IV per message |
| Padding oracle | RSA-OAEP used (not PKCS#1 v1.5) |
| Key persistence | All keys are ephemeral, never written to disk |

---

## 🚀 Quick Start

### 1. Install the dependency

```bash
pip install cryptography
# Ubuntu/Debian Python 3.12+:
pip install cryptography --break-system-packages
```

### 2. Make the wrapper executable

```bash
chmod +x chat.sh
```

### 3a. Same network (LAN/WiFi)

```bash
# Peer A
./chat.sh --host

# Peer B (use Peer A's local IP shown at startup)
./chat.sh --connect 192.168.1.42
```

### 3b. Over the Internet

```bash
# Peer A: forward TCP 5000 on your router first
./chat.sh --host --port 5000

# Peer B
./chat.sh --connect 203.0.113.7 --port 5000
```

### 3c. Local test (both peers on one machine)

```bash
python3 host.py               # terminal 1
python3 client.py 127.0.0.1  # terminal 2
```

---

## 💬 In-Chat Commands

| Command | Action |
|---|---|
| `/sendfile path/to/file` | Encrypt and send a file |
| `/history` | Show local chat history |
| `/help` | Show command reference |
| `/exit` | Gracefully disconnect |
| *(anything else)* | Send as a chat message |

### Message display

```
[12:01:05] You: Hello!
[12:01:07] Friend: Hey, is this encrypted?
[12:01:09] You: Yes — RSA handshake + AES Fernet 🔒
```

### File transfer

```
[12:05:00] You: /sendfile ~/Documents/report.pdf
  [→] Sending 'report.pdf'  (204,800 bytes, 4 chunk(s))...
  [████████████████████] 100%  chunk 4/4
  [✓] 'report.pdf' sent successfully.
```

Receiver sees:

```
  [←] Receiving 'report.pdf'  (204,800 bytes, 4 chunk(s))...
  [████████████████████] 100%  chunk 4/4
  [✓] Saved to 'received_files/report.pdf'  (204,800 bytes).
```

---

## 💾 Chat History (chat_history.json)

```json
[
  {
    "type": "message",
    "from": "you",
    "to": "peer",
    "message": "Hello!",
    "timestamp": "2026-04-12 12:01:05"
  },
  {
    "type": "file_sent",
    "filename": "report.pdf",
    "size": 204800,
    "timestamp": "2026-04-12 12:05:00"
  }
]
```

View with `/history` in-session, or open the file directly.

---

## 🌐 Finding Your IP Address

### Local (LAN) IP

```bash
hostname -I          # Linux
ifconfig | grep inet # macOS
ipconfig             # Windows
```

### Public (WAN) IP

```bash
curl ifconfig.me
```

Both are displayed automatically at startup by the tool.

---

## 🔧 Router Port Forwarding (for Internet use)

1. Log in to router admin panel (typically `http://192.168.1.1`)
2. Find Port Forwarding / NAT / Virtual Servers
3. Add a rule: Protocol=TCP, External Port=5000, Internal IP=your LAN IP, Internal Port=5000
4. Share your public IP with the client peer

---

## 📋 Dependencies

| Package | Purpose |
|---|---|
| `cryptography` | RSA-2048, Fernet (AES+HMAC) |

Everything else is Python stdlib: socket, threading, struct, json, base64, argparse, urllib.

---

## ⚠️ Limitations

- Single peer only — one host, one client per session
- No NAT traversal — requires direct reachability or port forwarding
- No persistent identity — keys are ephemeral (no PKI across sessions)
- chat_history.json is stored as plaintext locally
