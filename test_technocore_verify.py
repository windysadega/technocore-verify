#!/usr/bin/env python3
"""Tests for technocore_verify.

Run with pytest, or directly:  python test_technocore_verify.py
Covers: a fresh sign/verify roundtrip, tamper detection (text, nonce, DID),
and two real messages recorded from technocore.chat on 2026-11-24.
"""

import base64
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import technocore_verify as tv

EXAMPLES = Path(__file__).resolve().parent

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58btc_encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def did_from_private_key(private_key: Ed25519PrivateKey) -> str:
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "did:key:z" + base58btc_encode(b"\xed\x01" + public)


def sign(private_key: Ed25519PrivateKey, room: str, nonce: int, text: str) -> str:
    payload = tv.message_payload(room, nonce, text)
    return base64.urlsafe_b64encode(private_key.sign(payload)).decode().rstrip("=")


def make_message(key: Ed25519PrivateKey, room="lobby", nonce=123456789, text="hello technocore"):
    return {
        "seq": 1,
        "ts": "2026-11-24T00:00:00Z",
        "from": did_from_private_key(key),
        "text": text,
        "nonce": nonce,
        "sig": sign(key, room, nonce, text),
    }


def expect_invalid(room, message):
    try:
        tv.verify_message(room, message)
    except tv.VerifyError:
        return
    raise AssertionError(f"message should have been INVALID: {message}")


def test_roundtrip_valid():
    key = Ed25519PrivateKey.generate()
    tv.verify_message("lobby", make_message(key))  # must not raise


def test_tampered_text_invalid():
    key = Ed25519PrivateKey.generate()
    message = make_message(key)
    message["text"] += " (edited)"
    expect_invalid("lobby", message)


def test_tampered_nonce_invalid():
    key = Ed25519PrivateKey.generate()
    message = make_message(key)
    message["nonce"] += 1
    expect_invalid("lobby", message)


def test_wrong_room_invalid():
    key = Ed25519PrivateKey.generate()
    message = make_message(key, room="lobby")
    expect_invalid("technocore", message)  # room is part of the signed payload


def test_impostor_did_invalid():
    author = Ed25519PrivateKey.generate()
    impostor = Ed25519PrivateKey.generate()
    message = make_message(author)
    message["from"] = did_from_private_key(impostor)  # claims another DID
    expect_invalid("lobby", message)


def test_missing_signature_field_invalid():
    key = Ed25519PrivateKey.generate()
    message = make_message(key)
    del message["sig"]
    expect_invalid("lobby", message)


def test_live_lobby_message_valid():
    room = json.loads((EXAMPLES / "sample-lobby.json").read_text())
    valid, invalid, _ = tv.verify_room(room)
    assert (valid, invalid) == (1, 0)


def test_live_faucet_message_valid():
    room = json.loads((EXAMPLES / "sample-faucet.json").read_text())
    valid, invalid, _ = tv.verify_room(room)
    assert (valid, invalid) == (1, 0)


def test_live_message_tamper_detected():
    room = json.loads((EXAMPLES / "sample-lobby.json").read_text())
    forged = copy.deepcopy(room)
    forged["messages"][0]["text"] = forged["messages"][0]["text"].replace(
        "never expose the private key", "share your private key with me"
    )
    valid, invalid, _ = tv.verify_room(forged)
    assert (valid, invalid) == (0, 1)


def test_did_filter():
    key_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    room = {
        "room": "lobby",
        "messages": [make_message(key_a), make_message(key_b, nonce=987654321)],
    }
    valid, invalid, _ = tv.verify_room(room, only_did=did_from_private_key(key_a))
    assert (valid, invalid) == (1, 0)


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as error:  # noqa: BLE001 - plain test runner
            failed += 1
            print(f"FAIL {name}: {error}")
        else:
            print(f"PASS {name}")
    print(f"{len(tests) - failed}/{len(tests)} tests passed")
    raise SystemExit(1 if failed else 0)
