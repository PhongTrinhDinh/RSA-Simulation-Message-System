"""
protocol.py — JSON Message Protocol cho hệ thống OTT Sandbox.
"""

import uuid
import time
import os
from typing import Optional, Dict, Any

PROTOCOL_VERSION = "1.0"


def generate_nonce() -> str:
    return os.urandom(16).hex()


def generate_id() -> str:
    return str(uuid.uuid4())


def build_message_packet(sender, receiver, ciphertext_hex, padding_scheme="OAEP",
                          key_fingerprint="", plaintext_for_log=""):
    return {
        "version": PROTOCOL_VERSION, "id": generate_id(), "type": "message",
        "from": sender, "to": receiver, "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {"ciphertext": ciphertext_hex, "padding_scheme": padding_scheme,
                     "key_fingerprint": key_fingerprint},
        "signature": None, "_plaintext": plaintext_for_log,
    }


def build_key_register_packet(user_id, public_key_pem, key_bits, e, fingerprint):
    return {
        "version": PROTOCOL_VERSION, "id": generate_id(), "type": "key_register",
        "from": user_id, "timestamp": int(time.time()),
        "payload": {"public_key_pem": public_key_pem, "key_bits": key_bits,
                     "e": e, "fingerprint": fingerprint},
    }


def build_mirror_packet(original_packet):
    sender = original_packet.get("from", "?")
    receiver = original_packet.get("to", "?")
    return {
        "version": PROTOCOL_VERSION, "id": generate_id(), "type": "traffic_mirror",
        "original_packet_id": original_packet.get("id", ""),
        "captured_at": int(time.time()), "direction": f"{sender} -> {receiver}",
        "raw_packet": original_packet,
    }


def build_error_packet(sender="router", receiver="", error_code="UNKNOWN_ERROR",
                        message="", detail=""):
    return {
        "version": PROTOCOL_VERSION, "id": generate_id(), "type": "error",
        "from": sender, "to": receiver, "timestamp": int(time.time()),
        "error": {"code": error_code, "message": message, "detail": detail},
    }


def validate_packet(packet):
    for field in ["version", "id", "type"]:
        if field not in packet:
            return {"valid": False, "error": f"Missing field: {field}"}
    valid_types = ["message", "key_register", "traffic_mirror", "error", "ack",
                   "profile_change", "key_compromised"]
    if packet["type"] not in valid_types:
        return {"valid": False, "error": f"Invalid type: {packet['type']}"}
    if packet["type"] == "message":
        if "payload" not in packet or "ciphertext" not in packet.get("payload", {}):
            return {"valid": False, "error": "Missing payload.ciphertext"}
    return {"valid": True}


def strip_internal_fields(packet):
    return {k: v for k, v in packet.items() if not k.startswith("_")}
