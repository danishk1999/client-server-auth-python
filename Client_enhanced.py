"""
Client_enhanced.py
------------------
Enhanced Secure Mail Transfer Protocol – Client side.

ATTACK DEFENDED: Replay Attack
────────────────────────────────
See Server_enhanced.py for a full description of the attack and defence.

Every message sent by the client is wrapped in a nonce+timestamp envelope
(24 bytes prepended before the payload) before being AES-ECB encrypted.
The server validates both the timestamp and the nonce's uniqueness.

Envelope layout (before encryption):
    bytes  0- 7  : UNIX timestamp as big-endian uint64
    bytes  8-23  : random nonce (16 bytes)
    bytes 24-    : actual payload

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
AES_BLOCK               = 16
NONCE_SIZE              = 16
TIMESTAMP_TOLERANCE_SEC = 60
MAX_TITLE_LEN           = 100
MAX_CONTENT_LEN         = 1_000_000


# ── Crypto helpers ───────────────────────────────────────────────────────────

def load_private_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_public_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_encrypt(plaintext, public_key):
    return PKCS1_OAEP.new(public_key).encrypt(plaintext)


def rsa_decrypt(ciphertext, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(ciphertext)


def aes_encrypt(plaintext, sym_key):
    return AES.new(sym_key, AES.MODE_ECB).encrypt(pad(plaintext, AES_BLOCK))


def aes_decrypt(ciphertext, sym_key):
    return unpad(AES.new(sym_key, AES.MODE_ECB).decrypt(ciphertext), AES_BLOCK)


# ── Nonce/Timestamp envelope ──────────────────────────────────────────────────

def wrap_message(payload: bytes) -> bytes:
    """Prepend 8-byte timestamp + 16-byte nonce to payload."""
    ts    = struct.pack(">Q", int(time.time()))
    nonce = get_random_bytes(NONCE_SIZE)
    return ts + nonce + payload


def unwrap_message(envelope: bytes, seen_nonces: set,
                   tolerance: int = TIMESTAMP_TOLERANCE_SEC) -> bytes:
    """
    Validate timestamp and nonce, return payload.
    Raises ValueError on failure (stale or replayed message).
    """
    if len(envelope) < 8 + NONCE_SIZE:
        raise ValueError("Envelope too short.")

    ts_bytes = envelope[:8]
    nonce    = envelope[8:8 + NONCE_SIZE]
    payload  = envelope[8 + NONCE_SIZE:]

    msg_time = struct.unpack(">Q", ts_bytes)[0]
    now      = int(time.time())
    if abs(now - msg_time) > tolerance:
        raise ValueError(
            f"[REPLAY DEFENCE] Timestamp out of range "
            f"(delta={abs(now-msg_time)}s). Message rejected."
        )

    if nonce in seen_nonces:
        raise ValueError(
            "[REPLAY DEFENCE] Duplicate nonce. Possible replay. Rejected."
        )
    seen_nonces.add(nonce)
    return payload


# ── Network helpers ──────────────────────────────────────────────────────────

def recv_all(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(min(BUFFER_SIZE, n - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        data += chunk
    return data


def send_prefixed(s, data):
    s.sendall(len(data).to_bytes(8, byteorder="big") + data)


def recv_prefixed(s):
    header  = recv_all(s, 8)
    pay_len = int.from_bytes(header, byteorder="big")
    return recv_all(s, pay_len)


# ── Encrypted send / receive with envelope ───────────────────────────────────

def secure_send(s, payload: bytes, sym_key: bytes) -> None:
    """Wrap payload, AES-encrypt, send."""
    envelope = wrap_message(payload)
    send_prefixed(s, aes_encrypt(envelope, sym_key))


def secure_recv(s, sym_key: bytes, seen_nonces: set) -> bytes:
    """Receive, AES-decrypt, validate and unwrap envelope."""
    ciphertext = recv_prefixed(s)
    envelope   = aes_decrypt(ciphertext, sym_key)
    return unwrap_message(envelope, seen_nonces)


# ── Email construction ───────────────────────────────────────────────────────

def build_email(from_user, to_users, title, content):
    if len(title) > MAX_TITLE_LEN:
        print(f"Error: title exceeds {MAX_TITLE_LEN} characters.")
        return None
    if len(content) > MAX_CONTENT_LEN:
        print(f"Error: content exceeds {MAX_CONTENT_LEN} characters.")
        return None
    return (f"From: {from_user}\n"
            f"To: {to_users}\n"
            f"Title: {title}\n"
            f"Content Length: {len(content)}\n"
            f"Content:\n"
            f"{content}")


# ── Sub-protocol handlers ────────────────────────────────────────────────────

def handle_send_email(s, sym_key, username, seen_nonces):
    # Receive and validate "Send the email" prompt
    try:
        secure_recv(s, sym_key, seen_nonces)   # consume prompt
    except ValueError as e:
        print(f"[REPLAY DEFENCE] Prompt rejected: {e}")
        return

    destinations = input("Enter destinations (separated by ;): ").strip()
    title        = input("Enter title: ").strip()
    if len(title) > MAX_TITLE_LEN:
        print("Error: title too long. Email aborted.")
        return

    load_file = input("Would you like to load contents from a file?(Y/N) ").strip().upper()
    if load_file == "Y":
        filename = input("Enter filename: ").strip()
        try:
            with open(filename, "r") as f:
                content = f.read()
        except FileNotFoundError:
            print(f"Error: file '{filename}' not found.")
            return
    else:
        content = input("Enter message contents: ")

    if len(content) > MAX_CONTENT_LEN:
        print("Error: content too long. Email aborted.")
        return

    email = build_email(username, destinations, title, content)
    if email is None:
        return

    secure_send(s, email.encode("utf-8"), sym_key)
    print("The message is sent to the server.")


def handle_view_inbox(s, sym_key, seen_nonces):
    try:
        inbox_bytes = secure_recv(s, sym_key, seen_nonces)
    except ValueError as e:
        print(f"[REPLAY DEFENCE] Inbox data rejected: {e}")
        return
    print(inbox_bytes.decode("utf-8"))
    secure_send(s, b"OK", sym_key)


def handle_view_email(s, sym_key, seen_nonces):
    try:
        secure_recv(s, sym_key, seen_nonces)   # consume index request
    except ValueError as e:
        print(f"[REPLAY DEFENCE] Index request rejected: {e}")
        return

    idx = input("Enter the email index you wish to view: ").strip()
    secure_send(s, idx.encode("utf-8"), sym_key)

    try:
        email_bytes = secure_recv(s, sym_key, seen_nonces)
        print(email_bytes.decode("utf-8"))
    except ValueError as e:
        print(f"[REPLAY DEFENCE] Email content rejected: {e}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    server_public_key  = load_public_key("server_public.pem")
    server_host        = input("Enter the server IP or name: ").strip()
    username           = input("Enter your username: ").strip()
    password           = input("Enter your password: ").strip()
    client_private_key = load_private_key(f"{username}_private.pem")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((server_host, PORT))
    except Exception as e:
        print(f"Could not connect to server: {e}")
        sys.exit(1)

    # Nonce store for this session
    seen_nonces: set = set()

    # ── Step 1: Send RSA-encrypted credential envelope ────────────────────────
    # Wrap credentials in nonce+timestamp envelope, THEN RSA-encrypt.
    creds_plain = f"{username}\n{password}".encode("utf-8")
    creds_env   = wrap_message(creds_plain)
    send_prefixed(s, rsa_encrypt(creds_env, server_public_key))
    print("[Enhanced] Credentials sent with replay-protection envelope.")

    # ── Step 3a: Read server response ────────────────────────────────────────
    try:
        response = recv_prefixed(s)
    except Exception:
        print("Connection closed by server.")
        s.close()
        sys.exit(1)

    try:
        decoded = response.decode("utf-8")
        if decoded == "Invalid username or password":
            print("Invalid username or password.\nTerminating.")
            s.close()
            sys.exit(0)
    except UnicodeDecodeError:
        pass

    # ── Step 3b: Decrypt symmetric key ───────────────────────────────────────
    try:
        sym_key = rsa_decrypt(response, client_private_key)
    except Exception:
        print("Failed to decrypt symmetric key. Terminating.")
        s.close()
        sys.exit(1)

    print("[Enhanced] Symmetric key received and decrypted.")

    # Send "OK" with envelope
    secure_send(s, b"OK", sym_key)

    # ── Steps 4-7: Main menu loop ─────────────────────────────────────────────
    while True:
        try:
            menu_bytes = secure_recv(s, sym_key, seen_nonces)
            menu_str   = menu_bytes.decode("utf-8")
        except ValueError as e:
            print(f"[REPLAY DEFENCE] Menu rejected: {e}")
            break
        except Exception:
            break

        print(menu_str, end="")
        choice = input("").strip()
        secure_send(s, choice.encode("utf-8"), sym_key)

        if choice == "1":
            handle_send_email(s, sym_key, username, seen_nonces)
        elif choice == "2":
            handle_view_inbox(s, sym_key, seen_nonces)
        elif choice == "3":
            handle_view_email(s, sym_key, seen_nonces)
        elif choice == "4":
            print("The connection is terminated with the server.")
            s.close()
            sys.exit(0)
        else:
            print("Invalid choice. Please select 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
