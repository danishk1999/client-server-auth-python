"""
key_generator.py
----------------
Generates RSA public/private key pairs for the server and 5 known clients.
Keys are stored as PEM files in the current directory.
Also generates the user_pass.json credentials file.

Usage: python3 key_generator.py
"""

import json
import os
from Crypto.PublicKey import RSA

# ── Configuration ────────────────────────────────────────────────────────────
KEY_SIZE   = 2048          # RSA key size in bits
CLIENTS    = ["client1", "client2", "client3", "client4", "client5"]
PASSWORDS  = {             # username → plaintext password (stored in JSON)
    "client1": "password1",
    "client2": "password2",
    "client3": "password3",
    "client4": "password4",
    "client5": "password5",
}

def generate_rsa_keypair(name_prefix: str) -> None:
    """
    Generate an RSA key pair and write:
        <name_prefix>_private.pem  – private key (PEM, not encrypted)
        <name_prefix>_public.pem   – public  key (PEM)
    """
    key = RSA.generate(KEY_SIZE)

    private_path = f"{name_prefix}_private.pem"
    public_path  = f"{name_prefix}_public.pem"

    # Write private key
    with open(private_path, "wb") as f:
        f.write(key.export_key("PEM"))
    print(f"  [OK] {private_path}")

    # Write public key
    with open(public_path, "wb") as f:
        f.write(key.publickey().export_key("PEM"))
    print(f"  [OK] {public_path}")


def create_client_folders() -> None:
    """Create one inbox folder per known client (used by the server)."""
    for username in CLIENTS:
        os.makedirs(username, exist_ok=True)
        print(f"  [OK] folder '{username}/'")


def generate_user_pass_json() -> None:
    """Write user_pass.json with username→password mappings."""
    with open("user_pass.json", "w") as f:
        json.dump(PASSWORDS, f, indent=4)
    print("  [OK] user_pass.json")


# ── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Generating server key pair ===")
    generate_rsa_keypair("server")

    print("\n=== Generating client key pairs ===")
    for client in CLIENTS:
        print(f"  -- {client} --")
        generate_rsa_keypair(client)

    print("\n=== Creating client inbox folders ===")
    create_client_folders()

    print("\n=== Writing user_pass.json ===")
    generate_user_pass_json()

    print("\nAll keys, folders and credential file generated successfully.")
