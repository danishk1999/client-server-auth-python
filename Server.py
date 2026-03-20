"""
Server.py
---------
Secure Mail Transfer Protocol – Server side.

Responsibilities:
  • Listen on TCP port 13000 for incoming client connections.
  • Fork a child process for each accepted connection so all 5 known
    clients can be served simultaneously.
  • Authenticate clients using RSA-encrypted credentials.
  • Exchange a freshly generated 256-bit AES symmetric key with every
    authenticated client (key is RSA-encrypted with the client's public key).
  • Use AES-ECB with the symmetric key for all subsequent communication.
  • Support four menu operations per session:
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

from Crypto.PublicKey  import RSA
from Crypto.Cipher     import PKCS1_OAEP, AES
from Crypto.Random     import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ── Constants ────────────────────────────────────────────────────────────────
PORT          = 13000
BUFFER_SIZE   = 2048          # bytes per recv() call
AES_KEY_SIZE  = 32            # 256-bit AES key
AES_BLOCK     = 16            # AES block size in bytes
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


def rsa_decrypt(ciphertext: bytes, private_key: RSA.RsaKey) -> bytes:
    """Decrypt bytes with an RSA private key using OAEP padding."""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def rsa_encrypt(plaintext: bytes, public_key: RSA.RsaKey) -> bytes:
    """Encrypt bytes with an RSA public key using OAEP padding."""
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)


def aes_encrypt(plaintext: bytes, sym_key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-ECB (as required by the spec).
    The plaintext is padded to a multiple of AES_BLOCK before encryption.
    """
    cipher = AES.new(sym_key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES_BLOCK))


def aes_decrypt(ciphertext: bytes, sym_key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-ECB and remove PKCS7 padding.
    """
    cipher = AES.new(sym_key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES_BLOCK)


# ── Network helpers ──────────────────────────────────────────────────────────

def recv_all(conn: socket.socket, expected_len: int) -> bytes:
    """
    Read exactly expected_len bytes from the socket.
    Loops over multiple recv() calls to guarantee the full message is received
    (spec requirement: server MUST ensure the full email is received).
    """
    data = b""
    while len(data) < expected_len:
        chunk = conn.recv(min(BUFFER_SIZE, expected_len - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed before full data received.")
        data += chunk
    return data


def send_prefixed(conn: socket.socket, data: bytes) -> None:
    """
    Send data prefixed with its 8-byte (big-endian) length so the receiver
    knows exactly how many bytes to read.
    """
    length_header = len(data).to_bytes(8, byteorder="big")
    conn.sendall(length_header + data)


def recv_prefixed(conn: socket.socket) -> bytes:
    """
    Receive a length-prefixed message.  First reads the 8-byte header to
    determine the payload size, then reads exactly that many bytes.
    """
    header = recv_all(conn, 8)
    payload_len = int.from_bytes(header, byteorder="big")
    return recv_all(conn, payload_len)


# ── Email helpers ────────────────────────────────────────────────────────────

def parse_email(raw: str) -> dict:
    """
    Parse a raw email string into a dictionary with keys:
    from, to, title, content_length, content.
    Returns None if the format is invalid.
    """
    try:
        lines  = raw.split("\n")
        result = {}
        # First four header lines are key: value pairs
        result["from"]           = lines[0].split(": ", 1)[1].strip()
        result["to"]             = lines[1].split(": ", 1)[1].strip()
        result["title"]          = lines[2].split(": ", 1)[1].strip()
        result["content_length"] = int(lines[3].split(": ", 1)[1].strip())
        # Line index 4 is "Content:" label, actual content starts at index 5
        result["content"]        = "\n".join(lines[5:])
        return result
    except Exception:
        return None


def get_inbox_files(username: str) -> list:
    """
    Return a sorted list of email file paths in the client's inbox folder.
    Sorted by file modification time (oldest first) to reflect received order.
    """
    pattern = os.path.join(username, "*.txt")
    files   = glob.glob(pattern)
    files.sort(key=os.path.getmtime)
    return files


def read_email_file(filepath: str) -> str:
    """Read and return the text content of an email file."""
    with open(filepath, "r") as f:
        return f.read()


# ── Per-client session handler ───────────────────────────────────────────────

def handle_client(conn: socket.socket, addr: tuple,
                  server_private_key: RSA.RsaKey,
                  user_pass: dict) -> None:
    """
    Full session handler executed in a forked child process.
    Implements the complete client/server protocol described in the spec.
    """

    # ── Step 1: Receive encrypted username+password ──────────────────────────
    try:
        encrypted_creds = recv_prefixed(conn)
        creds_plain     = rsa_decrypt(encrypted_creds, server_private_key)
        creds_str       = creds_plain.decode("utf-8")
        # Credentials are sent as "username\npassword"
        username, password = creds_str.split("\n", 1)
    except Exception:
        conn.close()
        return

    # ── Step 2: Validate credentials ─────────────────────────────────────────
    if username not in user_pass or user_pass[username] != password:
        # Send unencrypted rejection message
        conn.sendall(b"Invalid username or password")
        print(f"The received client information: {username} is invalid "
              f"(Connection Terminated).")
        conn.close()
        return

    # Valid user – generate a 256-bit AES symmetric key
    sym_key = get_random_bytes(AES_KEY_SIZE)

    # Encrypt sym_key with the client's public key
    client_pub_key_path = f"{username}_public.pem"
    client_public_key   = load_public_key(client_pub_key_path)
    encrypted_sym_key   = rsa_encrypt(sym_key, client_public_key)

    send_prefixed(conn, encrypted_sym_key)
    print(f"Connection Accepted and Symmetric Key Generated for client: {username}")

    # ── Step 3: Wait for "OK" confirmation from client ────────────────────────
    try:
        ok_enc  = recv_prefixed(conn)
        ok_msg  = aes_decrypt(ok_enc, sym_key).decode("utf-8")
        if ok_msg != "OK":
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
        # Send encrypted menu
        send_prefixed(conn, aes_encrypt(menu.encode("utf-8"), sym_key))

        # Receive client choice
        try:
            choice_enc = recv_prefixed(conn)
            choice     = aes_decrypt(choice_enc, sym_key).decode("utf-8").strip()
        except Exception:
            break

        if choice == "1":
            handle_send_email(conn, sym_key, username)
        elif choice == "2":
            handle_view_inbox(conn, sym_key, username)
        elif choice == "3":
            handle_view_email(conn, sym_key, username)
        else:
            # Choice "4" or anything unexpected – terminate
            handle_terminate(conn, username)
            return  # Child process exits after termination

    conn.close()


def handle_send_email(conn: socket.socket, sym_key: bytes,
                      username: str) -> None:
    """
    Sending Email Subprotocol (Section F of the spec).
    """
    # Step F-1: Tell client to send the email
    send_prefixed(conn, aes_encrypt(b"Send the email", sym_key))

    # Step F-2: Receive the email from the client
    try:
        email_enc = recv_prefixed(conn)
        email_raw = aes_decrypt(email_enc, sym_key).decode("utf-8")
    except Exception:
        return

    # Parse the received email
    email = parse_email(email_raw)
    if email is None:
        return

    # Validate title and content lengths (spec requirement)
    if len(email["title"]) > MAX_TITLE_LEN:
        return
    if email["content_length"] > MAX_CONTENT_LEN:
        return

    dest_usernames = email["to"].split(";")
    print(f"An email from {username} is sent to "
          f"{';'.join(dest_usernames)} has a content length of "
          f"{email['content_length']} .")

    # Step F-3: Add timestamp and save to each destination inbox
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
        dest_folder = dest
        if os.path.isdir(dest_folder):
            filename = os.path.join(dest_folder,
                                    f"{username}_{email['title']}.txt")
            with open(filename, "w") as f:
                f.write(full_email)


def handle_view_inbox(conn: socket.socket, sym_key: bytes,
                      username: str) -> None:
    """
    Viewing Inbox Subprotocol (Section G of the spec).
    """
    # Build inbox listing sorted by received date/time
    files = get_inbox_files(username)

    if not files:
        inbox_msg = "The inbox is empty.\n"
    else:
        header    = f"{'Index':<8}{'From':<12}{'DateTime':<30}{'Title'}\n"
        rows      = []
        for idx, filepath in enumerate(files, start=1):
            content = read_email_file(filepath)
            lines   = content.split("\n")
            # Extract sender, date-time and title from stored email headers
            from_val  = lines[0].split(": ", 1)[1].strip() if len(lines) > 0 else "?"
            dt_val    = lines[2].split(": ", 1)[1].strip() if len(lines) > 2 else "?"
            title_val = lines[3].split(": ", 1)[1].strip() if len(lines) > 3 else "?"
            rows.append(f"{idx:<8}{from_val:<12}{dt_val:<30}{title_val}")
        inbox_msg = header + "\n".join(rows) + "\n"

    send_prefixed(conn, aes_encrypt(inbox_msg.encode("utf-8"), sym_key))

    # Receive "OK" acknowledgement from client
    try:
        ok_enc = recv_prefixed(conn)
        aes_decrypt(ok_enc, sym_key)   # consume the OK
    except Exception:
        pass


def handle_view_email(conn: socket.socket, sym_key: bytes,
                      username: str) -> None:
    """
    Viewing Email Subprotocol (Section H of the spec).
    """
    # Step H-1: Ask client for an index
    send_prefixed(conn,
                  aes_encrypt(b"the server request email index", sym_key))

    # Step H-2: Receive the index from the client
    try:
        idx_enc = recv_prefixed(conn)
        idx_str = aes_decrypt(idx_enc, sym_key).decode("utf-8").strip()
        idx     = int(idx_str)
    except Exception:
        return

    # Step H-3: Retrieve the email and send it back
    files = get_inbox_files(username)
    if 1 <= idx <= len(files):
        email_content = read_email_file(files[idx - 1])
    else:
        email_content = "Invalid index.\n"

    send_prefixed(conn,
                  aes_encrypt(email_content.encode("utf-8"), sym_key))


def handle_terminate(conn: socket.socket, username: str) -> None:
    """
    Connection Termination Subprotocol (Section I of the spec).
    """
    print(f"Terminating connection with {username}.")
    conn.close()


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    # Load server private key
    server_private_key = load_private_key("server_private.pem")

    # Load user credentials from JSON
    with open("user_pass.json", "r") as f:
        user_pass = json.load(f)

    # Create TCP socket and start listening
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("", PORT))
    server_socket.listen(5)
    print("The server is ready to accept connections")

    while True:
        conn, addr = server_socket.accept()

        # Fork a child process to handle this client concurrently
        pid = os.fork()
        if pid == 0:
            # ── Child process ──
            server_socket.close()   # child does not need the listening socket
            handle_client(conn, addr, server_private_key, user_pass)
            conn.close()
            sys.exit(0)             # child exits cleanly after serving client
        else:
            # ── Parent process ──
            conn.close()            # parent closes its copy of the connection
            # Reap finished child processes to avoid zombies
            try:
                os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                pass


if __name__ == "__main__":
    main()
