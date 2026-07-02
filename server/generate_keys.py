"""
Run ONCE to generate both server keypairs.
    python3 generate_keys.py >> .env
Then confirm .env has both lines and the values have no surrounding quotes.
Never commit .env.
"""
from hpke_server import generate_server_keys

if __name__ == "__main__":
    k = generate_server_keys()
    print(f"SERVER_X25519_PRIVATE_KEY_HEX={k['SERVER_X25519_PRIVATE_KEY_HEX']}")
    print(f"SERVER_ED25519_PRIVATE_KEY_HEX={k['SERVER_ED25519_PRIVATE_KEY_HEX']}")
    print(f"# X25519 pub  (info only): {k['x25519_pub_hex']}")
    print(f"# Ed25519 pub (info only): {k['ed25519_pub_hex']}")
