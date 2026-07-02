#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "== Pure unit tests (no server) =="
python3 spike_hpke_roundtrip.py
echo

echo "== Generating throwaway key for this test run =="
export $(python3 generate_keys.py | grep SERVER_HPKE_PRIVATE_KEY_HEX)
echo "(generated)"
echo

echo "== Starting echo_server =="
(uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/echo_server.log 2>&1 &)
sleep 2

echo "== E2E OFF: plaintext echo =="
python3 test_plaintext.py
echo

echo "== E2E ON: HPKE-encrypted echo =="
python3 test_secure.py
echo

echo "== Toggle E2E on/off within ONE connection =="
python3 test_toggle_e2e.py
echo

echo "== Tamper rejection =="
python3 test_tamper.py

echo
echo "✅ All checks passed."
