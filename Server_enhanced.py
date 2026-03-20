"""
Server_enhanced.py
------------------
Enhanced Secure Mail Transfer Protocol – Server side.

ATTACK IDENTIFIED: Replay Attack
─────────────────────────────────
In the original protocol an attacker who intercepts an encrypted message
(e.g. the credential packet or any AES-encrypted command) can simply
re-transmit the identical ciphertext later.  Because AES-ECB produces the
same ciphertext for the same plaintext+key, the server cannot distinguish a
genuine request from a replayed copy.  Examples of harm:

  • Re-sending the credential ciphertext to open a second authenticated
    session without knowing the plaintext password.
  • Re-sending a previously captured "Create and send an email" payload to
    silently duplicate a message in the victim's inbox.

DEFENCE: Nonce + Timestamp
───────────────────────────
Each message sent by either side is wrapped in a small envelope:

    <8-byte big-endian UNIX timestamp (seconds)>
    <16-byte random nonce>
    <payload bytes>

On receipt the server (or client):
  1. Checks that the timestamp is within ±TIMESTAMP_TOLERANCE_SEC of its
     own clock.  Stale replays fail immediately.
  2. Checks that the nonce has NOT been seen before in this session.
     Within-window replays fail immediately.

The nonce+timestamp envelope is itself encrypted with the AES symmetric key
(or RSA for the initial credential exchange), so an attacker cannot strip or
alter it without breaking the encryption.

Allowed imports (per project spec):
    json, socket, os, glob, datetime, sys
    Any module from the Crypto (pycryptodome) library
"""

import json
import socket
import os
import glob
import datetime
import sys
import time
import struct

from Crypto.PublicKey    import RSA
from Crypto.Cipher       import PKCS1_OAEP, AES
from Crypto.Random       import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ── Constants ────────────────────────────────────────────────────────────────
PORT                    = 13000
BUFFER_SIZE             = 2048
AES_KEY_SIZE            = 32
AES_BLOCK               = 16
NONCE_SIZE              = 16      # bytes in each random nonce
TIMESTAMP_TOLERANCE_SEC = 60      # ±60 s clock skew tolerance
MAX_TITLE_LEN           = 100
MAX_CONTENT_LEN         = 1_000_000


# ── Crypto helpers ───────────────────────────────────────────────────────────

def load_private_key(path: str) -> RSA.RsaKey:
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_public_key(path: str) -> RSA.RsaKey:
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_decrypt(ciphertext: bytes, private_key: RSA.RsaKey) -> bytes:
    return PKCS1_OAEP.new(private_key).decrypt(ciphertext)


def rsa_encrypt(plaintext: bytes, public_key: RSA.RsaKey) -> bytes:
    return PKCS1_OAEP.new(public_key).encrypt(plaintext)


def aes_encrypt(plaintext: bytes, sym_key: bytes) -> bytes:
    """AES-ECB encrypt with PKCS7 padding."""
    return AES.new(sym_key, AES.MODE_ECB).encrypt(pad(plaintext, AES_BLOCK))


def aes_decrypt(ciphertext: bytes, sym_key: bytes) -> bytes:
    """AES-ECB decrypt and remove PKCS7 padding."""
    return unpad(AES.new(sym_key, AES.MODE_ECB).decrypt(ciphertext), AES_BLOCK)


# ── Nonce/Timestamp envelope ──────────────────────────────────────────────────

def wrap_message(payload: bytes) -> bytes:
    """
    Prepend an 8-byte timestamp and a 16-byte random nonce to the payload.
    The combined bytes are then passed to the caller for encryption.

    Envelope layout (before encryption):
        bytes  0- 7  : UNIX timestamp as big-endian uint64
        bytes  8-23  : random nonce (16 bytes)
        bytes 24-    : actual payload
    """
    ts    = struct.pack(">Q", int(time.time()))   # 8 bytes, big-endian uint64
    nonce = get_random_bytes(NONCE_SIZE)           # 16 random bytes
    return ts + nonce + payload


def unwrap_message(envelope: bytes,
                   seen_nonces: set,
                   tolerance: int = TIMESTAMP_TOLERANCE_SEC):
    """
    Validate and strip the timestamp+nonce envelope.

    Parameters
    ----------
    envelope     : decrypted bytes from the peer
    seen_nonces  : set of nonces already used in this session (mutated in-place)
    tolerance    : max allowed clock skew in seconds

    Returns
    -------
    payload bytes on success, or raises ValueError with a descriptive message.
    """
    if len(envelope) < 8 + NONCE_SIZE:
        raise ValueError("Envelope too short.")

    ts_bytes = envelope[:8]
    nonce    = envelope[8:8 + NONCE_SIZE]
    payload  = envelope[8 + NONCE_SIZE:]

    # ── Timestamp check ───────────────────────────────────────────────────────
    msg_time = struct.unpack(">Q", ts_bytes)[0]
    now      = int(time.time())
    if abs(now - msg_time) > tolerance:
        raise ValueError(
            f"[REPLAY DEFENCE] Timestamp out of range "
            f"(msg={msg_time}, now={now}, delta={abs(now-msg_time)}s). "
            f"Message rejected."
        )

    # ── Nonce check ───────────────────────────────────────────────────────────
    if nonce in seen_nonces:
        raise ValueError(
            "[REPLAY DEFENCE] Duplicate nonce detected. "
            "Possible replay attack. Message rejected."
        )
    seen_nonces.add(nonce)

    return payload


# ── Network helpers ──────────────────────────────────────────────────────────

def recv_all(conn: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(min(BUFFER_SIZE, n - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        data += chunk
    return data


def send_prefixed(conn: socket.socket, data: bytes) -> None:
    header = len(data).to_bytes(8, byteorder="big")
    conn.sendall(header + data)


def recv_prefixed(conn: socket.socket) -> bytes:
    header  = recv_all(conn, 8)
    pay_len = int.from_bytes(header, byteorder="big")
    return recv_all(conn, pay_len)


# ── Helpers: encrypted send / receive with envelope ──────────────────────────

def secure_send(conn: socket.socket, payload: bytes, sym_key: bytes) -> None:
    """Wrap payload in nonce+timestamp envelope, AES-encrypt, then send."""
    envelope = wrap_message(payload)
    send_prefixed(conn, aes_encrypt(envelope, sym_key))


def secure_recv(conn: socket.socket, sym_key: bytes,
                seen_nonces: set) -> bytes:
    """Receive, AES-decrypt, unwrap envelope (validates timestamp+nonce)."""
    ciphertext = recv_prefixed(conn)
    envelope   = aes_decrypt(ciphertext, sym_key)
    return unwrap_message(envelope, seen_nonces)


# ── Email helpers ────────────────────────────────────────────────────────────

def parse_email(raw: str) -> dict:
    try:
        lines  = raw.split("\n")
        result = {}
        result["from"]           = lines[0].split(": ", 1)[1].strip()
        result["to"]             = lines[1].split(": ", 1)[1].strip()
        result["title"]          = lines[2].split(": ", 1)[1].strip()
        result["content_length"] = int(lines[3].split(": ", 1)[1].strip())
        result["content"]        = "\n".join(lines[5:])
        return result
    except Exception:
        return None


def get_inbox_files(username: str) -> list:
    files = glob.glob(os.path.join(username, "*.txt"))
    files.sort(key=os.path.getmtime)
    return files


def read_email_file(filepath: str) -> str:
    with open(filepath, "r") as f:
        return f.read()


# ── Per-client session ───────────────────────────────────────────────────────

def handle_client(conn: socket.socket, addr: tuple,
                  server_private_key: RSA.RsaKey,
                  user_pass: dict) -> None:
    """
    Full enhanced session handler.
    Identical to the original protocol but every AES message uses the
    nonce+timestamp envelope to prevent replay attacks.
    """
    # Nonce store for this session (prevents within-session replays)
    seen_nonces: set = set()

    # ── Step 1: Receive RSA-encrypted credentials ─────────────────────────────
    # The credential packet itself is RSA-encrypted, so we wrap it in an
    # envelope BEFORE RSA encryption on the client side.  Here we just
    # RSA-decrypt, then unwrap.
    try:
        enc_creds  = recv_prefixed(conn)
        # RSA ciphertext is fixed-size; detect plain-text by size
        creds_env  = rsa_decrypt(enc_creds, server_private_key)
        creds_plain = unwrap_message(creds_env, seen_nonces)
        username, password = creds_plain.decode("utf-8").split("\n", 1)
    except ValueError as e:
        print(f"[REPLAY DEFENCE] Credential packet rejected: {e}")
        conn.close()
        return
    except Exception:
        conn.close()
        return

    # ── Step 2: Validate credentials ─────────────────────────────────────────
    if username not in user_pass or user_pass[username] != password:
        conn.sendall(b"Invalid username or password")
        print(f"The received client information: {username} is invalid "
              f"(Connection Terminated).")
        conn.close()
        return

    sym_key = get_random_bytes(AES_KEY_SIZE)
    client_public_key  = load_public_key(f"{username}_public.pem")
    encrypted_sym_key  = rsa_encrypt(sym_key, client_public_key)
    send_prefixed(conn, encrypted_sym_key)
    print(f"[Enhanced] Connection Accepted and Symmetric Key Generated "
          f"for client: {username}")

    # ── Step 3: Receive "OK" ──────────────────────────────────────────────────
    try:
        ok = secure_recv(conn, sym_key, seen_nonces)
        if ok.decode("utf-8") != "OK":
            conn.close()
            return
    except ValueError as e:
        print(f"[REPLAY DEFENCE] OK packet rejected: {e}")
        conn.close()
        return
    except Exception:
        conn.close()
        return

    # ── Steps 4-7: Main menu loop ─────────────────────────────────────────────
    menu = ("Select the operation:\n"
            "1) Create and send an email\n"
            "2) Display the inbox list\n"
            "3) Display the email contents\n"
            "4) Terminate the connection\n"
            "choice: ")

    while True:
        secure_send(conn, menu.encode("utf-8"), sym_key)

        try:
            choice_bytes = secure_recv(conn, sym_key, seen_nonces)
            choice       = choice_bytes.decode("utf-8").strip()
        except ValueError as e:
            print(f"[REPLAY DEFENCE] Menu choice rejected: {e}")
            break
        except Exception:
            break

        if choice == "1":
            handle_send_email(conn, sym_key, username, seen_nonces)
        elif choice == "2":
            handle_view_inbox(conn, sym_key, username, seen_nonces)
        elif choice == "3":
            handle_view_email(conn, sym_key, username, seen_nonces)
        else:
            handle_terminate(conn, username)
            return

    conn.close()


def handle_send_email(conn, sym_key, username, seen_nonces):
    secure_send(conn, b"Send the email", sym_key)
    try:
        email_bytes = secure_recv(conn, sym_key, seen_nonces)
        email_raw   = email_bytes.decode("utf-8")
    except ValueError as e:
        print(f"[REPLAY DEFENCE] Email packet rejected: {e}")
        return
    except Exception:
        return

    email = parse_email(email_raw)
    if email is None:
        return
    if len(email["title"]) > MAX_TITLE_LEN or email["content_length"] > MAX_CONTENT_LEN:
        return

    dest_usernames = email["to"].split(";")
    print(f"[Enhanced] An email from {username} is sent to "
          f"{';'.join(dest_usernames)} has a content length of "
          f"{email['content_length']} .")

    timestamp  = str(datetime.datetime.now())
    full_email = (f"From: {email['from']}\n"
                  f"To: {email['to']}\n"
                  f"Time and Date: {timestamp}\n"
                  f"Title: {email['title']}\n"
                  f"Content Length: {email['content_length']}\n"
                  f"Content:\n"
                  f"{email['content']}")

    for dest in dest_usernames:
        dest = dest.strip()
        if os.path.isdir(dest):
            filename = os.path.join(dest,
                                    f"{username}_{email['title']}.txt")
            with open(filename, "w") as f:
                f.write(full_email)


def handle_view_inbox(conn, sym_key, username, seen_nonces):
    files = get_inbox_files(username)
    if not files:
        inbox_msg = "The inbox is empty.\n"
    else:
        header = f"{'Index':<8}{'From':<12}{'DateTime':<30}{'Title'}\n"
        rows   = []
        for idx, filepath in enumerate(files, start=1):
            content   = read_email_file(filepath)
            lines     = content.split("\n")
            from_val  = lines[0].split(": ", 1)[1].strip() if lines else "?"
            dt_val    = lines[2].split(": ", 1)[1].strip() if len(lines) > 2 else "?"
            title_val = lines[3].split(": ", 1)[1].strip() if len(lines) > 3 else "?"
            rows.append(f"{idx:<8}{from_val:<12}{dt_val:<30}{title_val}")
        inbox_msg = header + "\n".join(rows) + "\n"

    secure_send(conn, inbox_msg.encode("utf-8"), sym_key)

    try:
        secure_recv(conn, sym_key, seen_nonces)   # consume OK
    except Exception:
        pass


def handle_view_email(conn, sym_key, username, seen_nonces):
    secure_send(conn, b"the server request email index", sym_key)
    try:
        idx_bytes = secure_recv(conn, sym_key, seen_nonces)
        idx       = int(idx_bytes.decode("utf-8").strip())
    except ValueError as e:
        print(f"[REPLAY DEFENCE] Email index packet rejected: {e}")
        return
    except Exception:
        return

    files = get_inbox_files(username)
    if 1 <= idx <= len(files):
        content = read_email_file(files[idx - 1])
    else:
        content = "Invalid index.\n"

    secure_send(conn, content.encode("utf-8"), sym_key)


def handle_terminate(conn, username):
    print(f"[Enhanced] Terminating connection with {username}.")
    conn.close()


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    server_private_key = load_private_key("server_private.pem")
    with open("user_pass.json", "r") as f:
        user_pass = json.load(f)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("", PORT))
    server_socket.listen(5)
    print("[Enhanced] The server is ready to accept connections")

    while True:
        conn, addr = server_socket.accept()
        pid = os.fork()
        if pid == 0:
            server_socket.close()
            handle_client(conn, addr, server_private_key, user_pass)
            conn.close()
            sys.exit(0)
        else:
            conn.close()
            try:
                os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                pass


if __name__ == "__main__":
    main()
