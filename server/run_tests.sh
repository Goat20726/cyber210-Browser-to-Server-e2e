#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "== Crypto unit tests (no server) =="
python3 test_crypto_unit.py
echo

echo "== Full handshake integration test =="
python3 -c "
import subprocess, time, os, sys
sys.path.insert(0, '.')
import hpke_server as h

k = h.generate_server_keys()
env = {**os.environ,
       'SERVER_X25519_PRIVATE_KEY_HEX':  k['SERVER_X25519_PRIVATE_KEY_HEX'],
       'SERVER_ED25519_PRIVATE_KEY_HEX': k['SERVER_ED25519_PRIVATE_KEY_HEX']}

srv = subprocess.Popen(
    ['uvicorn','main:app','--host','0.0.0.0','--port','8000'],
    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(2)
ret = subprocess.run([sys.executable, 'test_handshake.py'], env=env)
srv.terminate()
sys.exit(ret.returncode)
"

echo
echo "✅ All checks passed."
