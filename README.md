# 🔒 Client-Server Authentication — Python
**Course:** CMPT 361 — Intro to Networks  
**Institution:** MacEwan University  
**Status:** ✅ Completed

## Overview
Implemented a client-server authentication system using Python socket 
programming. The system supports multiple simultaneous client connections 
to a single server, with secure authentication and file transfer capabilities 
including PDF and other file types.

## Features
- Multiple clients connecting to one server simultaneously
- Secure user authentication protocol
- File transfer support (PDF and other file formats)
- Socket-based communication using Python
- Server-side client management and session handling

## Technologies Used
- **Python** — Core programming language
- **Python Socket Library** — Low-level network communication
- **Threading** — Handling multiple simultaneous client connections
- **File I/O** — Reading and transferring files between client and server

## System Architecture
Client 1 ──┐
Client 2 ──┼──→ Server (Authentication + File Transfer)
Client 3 ──┘

## How It Works
1. Server starts and listens for incoming connections
2. Client connects and sends credentials for authentication
3. Server verifies credentials and grants or denies access
4. Authenticated clients can request file transfers from the server
5. Server handles multiple clients concurrently using threading

## Key Learnings
- Python socket programming fundamentals
- Client-server architecture design
- Multi-threaded server implementation
- Network authentication protocols
- File transfer over TCP sockets

## Usage
```bash
# Start the server
python server.py

# Connect a client
python client.py
```

## Note
This project was developed for academic purposes to demonstrate 
network programming and authentication concepts.
