# 🔒 P2P Secure Chat

A minimal, **pure peer-to-peer** secure terminal chat application — no servers,
no cloud, no intermediaries of any kind.

Two peers communicate directly over a **TCP socket**, with every message
protected by **RSA-2048 key exchange** and **AES-256 (Fernet) encryption**.

---

## ⚠️ Important: This Is a Pure P2P Application

> **No server is used — ever.**

The two machines communicate directly with each other.  
There is no central server, no message broker, no relay, no cloud service,
no WebSocket gateway, and no STUN/TURN infrastructure.

This also means:

| Scenario | Works? | Notes |
|---|---|---|
| Same WiFi / LAN | ✅ Yes | Use each other's local IP |
| Internet (different networks) | ✅ Yes | Requires public IP + port forwarding |
| Both behind NAT, no port forwarding | ❌ No | NAT traversal is out of scope by design |

---

## 🔐 Security Architecture

```
Peer A (host)                          Peer B (client)
─────────────────────────────────────────────────────────
Generate RSA-2048 key pair             Generate RSA-2048 key pair
                                       
Send RSA public key  ──────────────────────────────────>
                     <────────────────────────  Send RSA public key
                                       
Generate AES session key               
Encrypt AES key with B's RSA pub key   
Send encrypted AES key ────────────────────────────────>
                                       Decrypt AES key with own RSA priv key
                                       
[Both peers now share the same AES key — established without sending it in plaintext]

All subsequent messages: AES-Fernet encrypted (AES-128-CBC + HMAC-SHA256)
```

### Why this is secure

| Threat | Protection |
|---|---|
| Eavesdropping | All traffic is AES-encrypted after handshake |
| AES key interception | AES key is RSA-OAEP encrypted in transit |
| Message tampering | Fernet includes HMAC-SHA256 authentication |
| Key reuse | AES key and RSA keys are ephemeral (runtime only, never stored) |
| Padding oracle | RSA-OAEP used (not PKCS#1 v1.5) |
| IV reuse | Fernet generates a random IV per message |

---

## 📦 Project Structure

```
p2p_secure_chat/
├── host.py       — Listening peer (generates & distributes AES key)
├── client.py     — Connecting peer (receives & decrypts AES key)
├── crypto.py     — RSA + AES cryptographic primitives
├── chat.sh       — SSH-style CLI wrapper
└── README.md     — This file
```

---

## 🚀 Quick Start

### 1. Install the only dependency

```bash
pip install cryptography
```

On Ubuntu/Debian with Python 3.12+ (PEP 668):
```bash
pip install cryptography --break-system-packages
# or use a venv:
python3 -m venv .venv && source .venv/bin/activate && pip install cryptography
```

### 2. Make the wrapper executable

```bash
chmod +x chat.sh
```

### 3a. Same WiFi / LAN

**On Peer A's machine (host):**
```bash
./chat.sh --host
```

**On Peer B's machine (client) — find Peer A's LAN IP first:**
```bash
./chat.sh --connect 192.168.1.42
```

### 3b. Over the Internet

**On Peer A's machine (host):**
```bash
./chat.sh --host --port 5000
```

**On Peer B's machine (client):**
```bash
./chat.sh --connect <PEER_A_PUBLIC_IP> --port 5000
```

You can also call Python directly:

```bash
# Host
python3 host.py --port 5000

# Client
python3 client.py 192.168.1.42 --port 5000
```

---

## 🌐 Finding Your IP Address

### Local IP (LAN)

```bash
# Linux / macOS
hostname -I          # Linux
ifconfig | grep inet # macOS

# Windows
ipconfig
```

Look for an address like `192.168.x.x` or `10.x.x.x`.

### Public IP (Internet)

```bash
curl ifconfig.me
# or
curl https://api.ipify.org
```

---

## 🔧 Router Port Forwarding (Internet Use)

If Peer A is behind a home router (NAT), Peer B cannot reach them directly.
Peer A must configure **port forwarding** on their router.

**General steps (exact UI varies by router brand):**

1. Log in to your router admin panel (usually `http://192.168.1.1` or `http://192.168.0.1`)
2. Find **Port Forwarding** (sometimes under "NAT", "Virtual Servers", or "Advanced")
3. Create a new rule:

| Field | Value |
|---|---|
| Protocol | TCP |
| External Port | 5000 (or your chosen port) |
| Internal IP | Your computer's LAN IP (e.g. `192.168.1.42`) |
| Internal Port | 5000 |

4. Save and apply.
5. Share your **public IP** (not LAN IP) with Peer B.

> **Note:** If both users are behind NAT and neither has port forwarding configured,
> this tool cannot establish a direct connection. Use the same local network,
> or configure port forwarding on one side.

---

## 💬 Chat Usage

Once connected, both terminals show:

```
🔐 Secure channel established. Start chatting!

──────────────────────────────────────────────
You: hello!
Friend: hey, is this really encrypted?
You: yes — RSA handshake + AES Fernet 🔒
```

- **`You:`** — your outgoing messages  
- **`Friend:`** — messages received from peer  
- Press **Ctrl-C** on either side to disconnect gracefully.

---

## ⚙️ Configuration Options

| Flag | Default | Description |
|---|---|---|
| `--port PORT` | `5000` | TCP port to listen on / connect to |
| `--host` | — | Run as the listening peer |
| `--connect IP` | — | Run as the connecting peer |

---

## 🧪 Local Test (both peers on the same machine)

```bash
# Terminal 1
python3 host.py --port 5000

# Terminal 2
python3 client.py 127.0.0.1 --port 5000
```

---

## 📋 Dependencies

| Package | Purpose | Install |
|---|---|---|
| `cryptography` | RSA + Fernet (AES) | `pip install cryptography` |

Everything else uses the Python standard library: `socket`, `threading`, `struct`, `argparse`.

---

## ⚠️ Limitations & Scope

- **Single-peer only** — one host, one client. No group chat.
- **No NAT traversal** — both peers must be directly reachable (same LAN or port-forwarded).
- **No persistent keys** — keys are generated fresh every session (no identity verification between sessions).
- **No file transfer** — text messages only.
- **No message history** — messages are not stored anywhere.

---

## 📄 License

MIT — use freely, modify freely.
