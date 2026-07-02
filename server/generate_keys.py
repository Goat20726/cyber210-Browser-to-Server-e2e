"""
Run this ONCE to generate the server's persistent HPKE keypair, per
Aura's direction: the server's identity should be loaded from .env, not
regenerated randomly every process start.

    python3 generate_keys.py >> .env

Then check .env actually has the line (>> appends, doesn't overwrite
anything else already in there). .env is gitignored -- never commit it.
Whoever deploys to .211/.221 needs their own copy of this value, shared
out-of-band (Slack DM, not committed to the repo).
"""
from hpke_server import generate_server_keypair, private_key_to_hex, pubkey_to_hex

if __name__ == "__main__":
    kp = generate_server_keypair()
    print(f"SERVER_HPKE_PRIVATE_KEY_HEX={private_key_to_hex(kp)}")
    print(f"# corresponding public key (informational only, not a secret,")
    print(f"# not needed in .env -- the server derives it from the private")
    print(f"# key above): {pubkey_to_hex(kp)}")
