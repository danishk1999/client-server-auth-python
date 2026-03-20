# CMPT 361 – Secure Mail Transfer Protocol

A reasonably secure email transfer system built in Python 3, developed as a course project for CMPT 361 at MacEwan University.

The system implements a client-server architecture where five known clients can securely exchange emails through a central mail server over TCP. All communication is protected using RSA public-key cryptography for authentication and AES-ECB for symmetric session encryption.

---

## Features

- **Mutual authentication** – clients authenticate to the server using RSA-encrypted credentials; the server responds with a freshly generated AES session key encrypted with the client's public key
- **Symmetric encryption** – all post-handshake traffic is AES-ECB encrypted using a per-session 256-bit key
- **Concurrent clients** – the server uses `os.fork()` to handle all five known clients simultaneously
- **Four mail operations** – send email, view inbox, read a specific email, terminate connection
- **Replay attack defence** – the enhanced protocol wraps every message in a nonce + timestamp envelope before encryption, blocking both delayed and immediate replay attacks

---

## Project Structure

```
.
├── key_generator.py        # Generates RSA key pairs and user_pass.json
├── Server.py               # Mail server (original protocol)
├── Client.py               # Mail client (original protocol)
├── Server_enhanced.py      # Mail server with replay-attack defence
├── Client_enhanced.py      # Mail client with replay-attack defence
└── README.md
```

> **Note:** `.pem` key files and `user_pass.json` are not committed to this repository. Generate them locally using `key_generator.py` before running the programs.

---

## Requirements

- Python 3.x
- [pycryptodome](https://pycryptodome.readthedocs.io/en/latest/src/installation.html)

```bash
pip install pycryptodome
```

---

## Setup

### 1. Generate keys and credentials

Run this once in the directory where the server will be hosted:

```bash
python3 key_generator.py
```

This creates:
- `server_private.pem` and `server_public.pem`
- `client1_private.pem` ... `client5_private.pem` (and matching public keys)
- `user_pass.json` with credentials for all five clients
- Inbox folders: `client1/` ... `client5/`

### 2. Distribute files to client machines

Each client machine needs:
- `Client.py` (or `Client_enhanced.py`)
- `server_public.pem`
- `[username]_private.pem` and `[username]_public.pem` for that client

---

## Usage

### Start the server

```bash
python3 Server.py
```

```
The server is ready to accept connections
```

### Connect a client

```bash
python3 Client.py
```

```
Enter the server IP or name: cc5-212-05.macewan.ca
Enter your username: client1
Enter your password: password1

Select the operation:
1) Create and send an email
2) Display the inbox list
3) Display the email contents
4) Terminate the connection
choice:
```

### Start the enhanced server (replay-attack resistant)

```bash
python3 Server_enhanced.py
python3 Client_enhanced.py
```

---

## Protocol Overview

```
Client                                      Server
  |                                           |
  |── RSA-encrypt(username + password) ──────>|
  |                                           |── validate credentials
  |<── RSA-encrypt(AES session key) ──────────|
  |                                           |
  |── AES-encrypt("OK") ───────────────────>  |
  |                                           |
  |<── AES-encrypt(menu) ─────────────────────|
  |── AES-encrypt(choice) ──────────────────> |
  |                                           |
  |    ... subprotocol for chosen operation ...|
  |                                           |
  |── AES-encrypt("4") ────────────────────>  |── close connection
```

---

## Enhanced Protocol – Replay Attack Defence

### The attack

AES-ECB produces identical ciphertext for identical plaintext. An attacker who intercepts a packet can re-transmit it later without decrypting it, causing the server to repeat an action (e.g. re-authenticate a user or re-deliver an email).

### The defence

Every message is wrapped in a **nonce + timestamp envelope** before encryption:

```
[ 8 bytes: UNIX timestamp ] [ 16 bytes: random nonce ] [ payload ]
```

The receiver rejects the message if:
1. The timestamp is more than 60 seconds old (blocks delayed replays)
2. The nonce has already been seen in this session (blocks immediate replays)

---

## Allowed Imports (per course specification)

```python
import json
import socket
import os, glob, datetime
import sys
# Any module from the Crypto (pycryptodome) library
```

---

## Author

**Danish Kumar** – 3128352  
MacEwan University, CMPT 361 – Fall 2024
