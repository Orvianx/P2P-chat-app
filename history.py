"""
history.py — Local Chat History
================================
Appends every event (message, file send, file receive) to a local
JSON file so both peers have a full audit trail of the session.

Storage format  →  chat_history.json  (array of objects, one per line)
"""

import json
import os
from datetime import datetime

HISTORY_FILE = "chat_history.json"

# ── Internal helpers ──────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _load() -> list:
    """Load the existing history list, or return [] if file absent/corrupt."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save(records: list) -> None:
    """Persist the history list with readable indentation."""
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False)
    except OSError as e:
        print(f"[history] Warning: could not save history — {e}")


def _append(record: dict) -> None:
    records = _load()
    records.append(record)
    _save(records)


# ── Public API ────────────────────────────────────────────────────────────────

def log_message(sender: str, message: str, peer: str = "peer") -> None:
    """
    Record a chat message.

    Args:
        sender:  'you' or 'friend'
        message: plaintext content
        peer:    label for the remote peer (informational)
    """
    _append({
        "type":      "message",
        "from":      sender,
        "to":        peer if sender == "you" else "you",
        "message":   message,
        "timestamp": _now(),
    })


def log_file_sent(filename: str, size: int) -> None:
    """Record a file we successfully sent."""
    _append({
        "type":      "file_sent",
        "filename":  filename,
        "size":      size,
        "timestamp": _now(),
    })


def log_file_received(filename: str, size: int, saved_path: str) -> None:
    """Record a file we successfully received and saved."""
    _append({
        "type":       "file_received",
        "filename":   filename,
        "size":       size,
        "saved_to":   saved_path,
        "timestamp":  _now(),
    })


def show_history(limit: int = 50) -> None:
    """
    Pretty-print the last `limit` history entries to stdout.
    Called when the user types /history.
    """
    records = _load()
    if not records:
        print("  (no history yet)")
        return

    recent = records[-limit:]
    print(f"\n  ── Chat History (last {len(recent)} entries) ──")
    for r in recent:
        ts  = r.get("timestamp", "?")
        typ = r.get("type", "?")

        if typ == "message":
            who = "You" if r.get("from") == "you" else "Friend"
            print(f"  [{ts}] {who}: {r.get('message', '')}")

        elif typ == "file_sent":
            print(f"  [{ts}] → Sent file: {r.get('filename')}  ({r.get('size', 0):,} bytes)")

        elif typ == "file_received":
            print(f"  [{ts}] ← Received file: {r.get('filename')}  "
                  f"({r.get('size', 0):,} bytes)  saved → {r.get('saved_to')}")

        else:
            print(f"  [{ts}] {r}")
    print()
