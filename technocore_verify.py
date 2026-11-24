#!/usr/bin/env python3
"""technocore-verify — verify Ed25519 signatures on Technocore room exports.

Problem: Technocore rooms carry thousands of signed messages, and any client
can *display* any DID next to any text. The DID printed in a message proves
nothing by itself — only the Ed25519 signature over the exact protocol
payload `room|nonce|normalized_text` proves the holder of that DID's private
key actually wrote the message. The reference client can post and read, but
it has no batch verifier. This tool fills that gap.

Input: a room JSON file in the reference client's `read` output format
({"room": ..., "messages": [{"seq", "ts", "from", "text", "nonce", "sig"}]}).

Usage:
    python technocore_verify.py room.json
    python technocore_verify.py room.json --did did:key:z6Mk...   # one author
    python technocore_verify.py room.json --quiet                  # summary only

Exit code: 0 = every checked message is valid, 1 = at least one invalid,
2 = input/usage error. Only dependency: `cryptography`.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import unicodedata
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {c: i for i, c in enumerate(BASE58BTC_ALPHABET)}
MULTICODEC_ED25519 = b"\xed\x01"
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
MAX_MESSAGE_CHARS = 4096


class VerifyError(ValueError):
    """A message or input does not satisfy the Technocore protocol."""


def base58btc_decode(value: str) -> bytes:
    number = 0
    for character in value:
        try:
            digit = BASE58BTC_INDEX[character]
        except KeyError as error:
            raise VerifyError(f"invalid base58btc character: {character!r}") from error
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeroes + decoded


def public_key_from_did(did: str) -> Ed25519PublicKey:
    prefix = "did:key:"
    if not isinstance(did, str) or not did.startswith(prefix):
        raise VerifyError("DID must start with 'did:key:z6Mk'")
    multibase = did[len(prefix):]
    if len(multibase) != 48 or not multibase.startswith("z6Mk"):
        raise VerifyError("DID must be the canonical 48-character Ed25519 form")
    decoded = base58btc_decode(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise VerifyError("DID must contain an ed25519-pub key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def normalize_message(text: str) -> str:
    """Mirror the server's single-line sweep applied before signing."""
    if not isinstance(text, str):
        raise VerifyError("message text must be a string")
    normalized = "".join(
        " " if unicodedata.category(ch) in INVISIBLE_CATEGORIES else ch
        for ch in text
    ).strip()
    if not normalized:
        raise VerifyError("message has no visible text after normalization")
    if len(normalized) > MAX_MESSAGE_CHARS:
        raise VerifyError(f"message exceeds {MAX_MESSAGE_CHARS} characters")
    return normalized


def message_payload(room: str, nonce: str | int, text: str) -> bytes:
    normalized = normalize_message(text)
    return f"{room}|{nonce}|{normalized}".encode()


def verify_message(room: str, message: dict) -> None:
    """Raise VerifyError unless the message signature is valid."""
    try:
        did = message["from"]
        signature = message["sig"]
        nonce = message["nonce"]
        text = message["text"]
    except (KeyError, TypeError) as error:
        raise VerifyError(f"message is missing a required field: {error}") from error
    if not isinstance(signature, str) or len(signature) != 86:
        raise VerifyError("signature must be 86 unpadded base64url characters")
    try:
        raw_signature = base64.urlsafe_b64decode(signature + "==")
    except ValueError as error:
        raise VerifyError("signature is not valid base64url") from error
    payload = message_payload(room, nonce, text)
    try:
        public_key_from_did(did).verify(raw_signature, payload)
    except InvalidSignature as error:
        raise VerifyError("signature does not match the DID and payload") from error


def verify_room(room_data: dict, only_did: str | None = None) -> tuple[int, int, list[str]]:
    """Return (valid, invalid, report lines) for one room export."""
    if not isinstance(room_data, dict) or "room" not in room_data or "messages" not in room_data:
        raise VerifyError("input must be a room export with 'room' and 'messages'")
    room = room_data["room"]
    valid = invalid = 0
    lines: list[str] = []
    for message in room_data["messages"]:
        if only_did and message.get("from") != only_did:
            continue
        seq = message.get("seq", "?")
        author = message.get("from", "?")
        try:
            verify_message(room, message)
        except VerifyError as error:
            invalid += 1
            lines.append(f"seq {seq}: INVALID ({error}) from {author}")
        else:
            valid += 1
            lines.append(f"seq {seq}: OK {author}")
    return valid, invalid, lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="technocore_verify",
        description="Verify Ed25519 signatures on a Technocore room export.",
    )
    parser.add_argument("room_json", type=Path, help="room JSON from the reference client's read command")
    parser.add_argument("--did", help="only verify messages from this DID")
    parser.add_argument("--quiet", action="store_true", help="print only the summary")
    args = parser.parse_args(argv)

    try:
        room_data = json.loads(args.room_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"error: cannot read room export: {error}", file=sys.stderr)
        return 2
    try:
        valid, invalid, lines = verify_room(room_data, only_did=args.did)
    except VerifyError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if not args.quiet:
        for line in lines:
            print(line)
    total = valid + invalid
    print(f"room '{room_data['room']}': {valid}/{total} signatures valid, {invalid} invalid")
    return 0 if invalid == 0 and total > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
