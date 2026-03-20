"""
Client.py
---------
Secure Mail Transfer Protocol – Client side.

Responsibilities:
  • Connect to the mail server over TCP on port 13000.
  • Prompt for credentials, RSA-encrypt them with the server's public key,
    and send them to the server.
  • Receive and RSA-decrypt the AES symmetric key sent by the server.
  • Use AES-ECB with sym_key for all subsequent communication.
  • Present the server's menu and handle four operations:
        1 – Create and send an email
        2 – Display inbox list
        3 – Display a single email
        4 – Terminate the connection

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

from Crypto.PublicKey    import RSA
from Crypto.Cipher       import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad


# ── Constants ────────────────────────────────────────────────────────────────
PORT          = 13000
BUFFER_SIZE   = 2048
AES_BLOCK     = 16
MAX_TITLE_LEN = 100
MAX_CONTENT_LEN = 1_000_000


# ── Crypto helpers ───────────────────────────────────────────────────────────

def load_private_key(path: str) -> RSA.RsaKey:
    """Load and return an RSA private key from a PEM file."""
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_public_key(path: str) -> RSA.RsaKey:
    """Load and return an RSA public key from a PEM file."""
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_encrypt(plaintext: bytes, public_key: RSA.RsaKey) -> bytes:
    """Encrypt bytes with an RSA public key using OAEP padding."""
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)


def rsa_decrypt(ciphertext: bytes, private_key: RSA.RsaKey) -> bytes:
    """Decrypt bytes with an RSA private key using OAEP padding."""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def aes_encrypt(plaintext: bytes, sym_key: bytes) -> bytes:
    """Encrypt plaintext with AES-ECB and PKCS7 padding."""
    cipher = AES.new(sym_key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES_BLOCK))


def aes_decrypt(ciphertext: bytes, sym_key: bytes) -> bytes:
    """Decrypt ciphertext with AES-ECB and remove PKCS7 padding."""
    cipher = AES.new(sym_key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES_BLOCK)


# ── Network helpers ──────────────────────────────────────────────────────────

def recv_all(s: socket.socket, expected_len: int) -> bytes:
    """Read exactly expected_len bytes from the socket."""
    data = b""
    while len(data) < expected_len:
        chunk = s.recv(min(BUFFER_SIZE, expected_len - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed before full data received.")
        data += chunk
    return data


def send_prefixed(s: socket.socket, data: bytes) -> None:
    """Send data with an 8-byte big-endian length prefix."""
    header = len(data).to_bytes(8, byteorder="big")
    s.sendall(header + data)


def recv_prefixed(s: socket.socket) -> bytes:
    """Receive a length-prefixed message."""
    header      = recv_all(s, 8)
    payload_len = int.from_bytes(header, byteorder="big")
    return recv_all(s, payload_len)


# ── Email construction ───────────────────────────────────────────────────────

def build_email(from_user: str, to_users: str,
                title: str, content: str) -> str:
    """
    Construct the email string exactly as specified in Section D.
    Returns None if title or content exceed the allowed lengths.
    """
    if len(title) > MAX_TITLE_LEN:
        print(f"Error: title exceeds {MAX_TITLE_LEN} characters.")
        return None
    if len(content) > MAX_CONTENT_LEN:
        print(f"Error: content exceeds {MAX_CONTENT_LEN} characters.")
        return None

    content_length = len(content)
    email = (f"From: {from_user}\n"
             f"To: {to_users}\n"
             f"Title: {title}\n"
             f"Content Length: {content_length}\n"
             f"Content:\n"
             f"{content}")
    return email


# ── Sub-protocol handlers ────────────────────────────────────────────────────

def handle_send_email(s: socket.socket, sym_key: bytes,
                      username: str) -> None:
    """
    Sending Email Subprotocol – client side (Section F).
    """
    # Receive "Send the email" prompt from server
    prompt_enc = recv_prefixed(s)
    prompt     = aes_decrypt(prompt_enc, sym_key).decode("utf-8")
    # (prompt text is informational; we don't print it per sample output)

    # Collect email metadata from the user
    destinations = input("Enter destinations (separated by ;): ").strip()
    title        = input("Enter title: ").strip()

    # Validate title length client-side
    if len(title) > MAX_TITLE_LEN:
        print(f"Error: title exceeds {MAX_TITLE_LEN} characters. Email aborted.")
        return

    # Get message content
    load_from_file = input("Would you like to load contents from a file?(Y/N) ").strip().upper()
    if load_from_file == "Y":
        filename = input("Enter filename: ").strip()
        try:
            with open(filename, "r") as f:
                content = f.read()
        except FileNotFoundError:
            print(f"Error: file '{filename}' not found. Email aborted.")
            return
    else:
        content = input("Enter message contents: ")

    # Validate content length client-side
    if len(content) > MAX_CONTENT_LEN:
        print(f"Error: content exceeds {MAX_CONTENT_LEN} characters. Email aborted.")
        return

    # Build and send the email
    email = build_email(username, destinations, title, content)
    if email is None:
        return

    send_prefixed(s, aes_encrypt(email.encode("utf-8"), sym_key))
    print("The message is sent to the server.")


def handle_view_inbox(s: socket.socket, sym_key: bytes) -> None:
    """
    Viewing Inbox Subprotocol – client side (Section G).
    """
    # Receive and print the inbox listing
    inbox_enc = recv_prefixed(s)
    inbox_str = aes_decrypt(inbox_enc, sym_key).decode("utf-8")
    print(inbox_str)

    # Send "OK" acknowledgement
    send_prefixed(s, aes_encrypt(b"OK", sym_key))


def handle_view_email(s: socket.socket, sym_key: bytes) -> None:
    """
    Viewing Email Subprotocol – client side (Section H).
    """
    # Receive index request from server
    req_enc = recv_prefixed(s)
    aes_decrypt(req_enc, sym_key)   # consume the request message

    # Ask user which email to view
    idx = input("Enter the email index you wish to view: ").strip()
    send_prefixed(s, aes_encrypt(idx.encode("utf-8"), sym_key))

    # Receive and print the requested email
    email_enc = recv_prefixed(s)
    email_str = aes_decrypt(email_enc, sym_key).decode("utf-8")
    print(email_str)


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    # Load the server's public key (pre-stored on the client machine)
    server_public_key = load_public_key("server_public.pem")

    # Prompt for server address and credentials
    server_host = input("Enter the server IP or name: ").strip()
    username    = input("Enter your username: ").strip()
    password    = input("Enter your password: ").strip()

    # Load the client's own private key
    client_private_key = load_private_key(f"{username}_private.pem")

    # ── Connect to the server ─────────────────────────────────────────────────
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((server_host, PORT))
    except Exception as e:
        print(f"Could not connect to server: {e}")
        sys.exit(1)

    # ── Step 1: Send RSA-encrypted credentials ────────────────────────────────
    creds_plain     = f"{username}\n{password}".encode("utf-8")
    encrypted_creds = rsa_encrypt(creds_plain, server_public_key)
    send_prefixed(s, encrypted_creds)

    # ── Step 3a: Read server response (could be rejection or encrypted sym_key) ─
    # The rejection message is sent unencrypted and is shorter than an RSA ciphertext.
    # We peek at the raw response: if it matches the rejection string, handle it.
    try:
        response = recv_prefixed(s)
    except Exception:
        print("Connection closed by server.")
        s.close()
        sys.exit(1)

    # Check for plain-text rejection
    try:
        decoded = response.decode("utf-8")
        if decoded == "Invalid username or password":
            print("Invalid username or password.\nTerminating.")
            s.close()
            sys.exit(0)
    except UnicodeDecodeError:
        pass  # Binary data → it's the encrypted symmetric key

    # ── Step 3b: Decrypt the symmetric key ───────────────────────────────────
    try:
        sym_key = rsa_decrypt(response, client_private_key)
    except Exception:
        print("Failed to decrypt symmetric key. Terminating.")
        s.close()
        sys.exit(1)

    # Send "OK" back to server, encrypted with sym_key
    send_prefixed(s, aes_encrypt(b"OK", sym_key))

    # ── Steps 4-7: Main menu loop ─────────────────────────────────────────────
    while True:
        # Receive and display the menu
        try:
            menu_enc = recv_prefixed(s)
            menu_str = aes_decrypt(menu_enc, sym_key).decode("utf-8")
        except Exception:
            break

        print(menu_str, end="")
        choice = input("").strip()

        # Send choice to server
        send_prefixed(s, aes_encrypt(choice.encode("utf-8"), sym_key))

        if choice == "1":
            handle_send_email(s, sym_key, username)
        elif choice == "2":
            handle_view_inbox(s, sym_key)
        elif choice == "3":
            handle_view_email(s, sym_key)
        elif choice == "4":
            # Connection Termination Subprotocol – client side (Section I)
            print("The connection is terminated with the server.")
            s.close()
            sys.exit(0)
        else:
            print("Invalid choice. Please select 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
