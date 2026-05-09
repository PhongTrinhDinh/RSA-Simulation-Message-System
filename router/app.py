"""
Router Server — Central Server cho OTT Sandbox.
Quản lý Public Key Directory, định tuyến tin nhắn, mirror traffic đến Eve.
"""
import os
import sys
import json
import time
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Dict, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Thêm shared vào path
sys.path.insert(0, "/app/shared")
import database as db
from profiles import get_profile, list_profiles, PROFILES

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("router")

# ── WebSocket Connection Manager ──

class ConnectionManager:
    def __init__(self):
        self.user_connections: Dict[str, WebSocket] = {}
        self.monitor_connections: List[WebSocket] = []

    async def connect_user(self, user_id: str, ws: WebSocket):
        await ws.accept()
        self.user_connections[user_id] = ws
        logger.info(f"[WS] {user_id} connected")

    async def connect_monitor(self, ws: WebSocket):
        await ws.accept()
        self.monitor_connections.append(ws)
        logger.info(f"[WS] Monitor connected (total: {len(self.monitor_connections)})")

    def disconnect_user(self, user_id: str):
        self.user_connections.pop(user_id, None)
        logger.info(f"[WS] {user_id} disconnected")

    def disconnect_monitor(self, ws: WebSocket):
        if ws in self.monitor_connections:
            self.monitor_connections.remove(ws)

    async def send_to_user(self, user_id: str, data: dict):
        ws = self.user_connections.get(user_id)
        if ws:
            try:
                await ws.send_json(data)
            except:
                self.disconnect_user(user_id)

    async def broadcast_to_monitors(self, data: dict):
        dead = []
        for ws in self.monitor_connections:
            try:
                await ws.send_json(data)
            except:
                dead.append(ws)
        for ws in dead:
            self.disconnect_monitor(ws)

    async def broadcast_to_all_users(self, data: dict):
        dead = []
        for uid, ws in self.user_connections.items():
            try:
                await ws.send_json(data)
            except:
                dead.append(uid)
        for uid in dead:
            self.disconnect_user(uid)

    def get_online_users(self):
        return list(self.user_connections.keys())


manager = ConnectionManager()

# ── App ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    logger.info("Router started. DB initialized.")
    yield

app = FastAPI(title="OTT Sandbox Router", lifespan=lifespan)

# ── Pydantic Models ──

class RegisterRequest(BaseModel):
    user_id: str
    public_key_pem: str
    key_bits: int = 0
    e: int = 0
    fingerprint: str = ""

class MessageRequest(BaseModel):
    sender: str  # Compat: also accept 'from' via alias
    to: str
    ciphertext: str
    padding_scheme: str = "OAEP"
    key_fingerprint: str = ""
    nonce: str = ""
    plaintext: str = ""  # For logging only

class ProfileRequest(BaseModel):
    profile: str

# ── Health ──

@app.get("/health")
async def health():
    return {"status": "ok", "service": "router", "timestamp": int(time.time())}

# ── Public Key Directory ──

@app.post("/register")
async def register_pubkey(req: RegisterRequest):
    profile_name = db.get_config("active_profile", "safe")
    profile = get_profile(profile_name)
    allow_override = profile.get("allow_pubkey_override", False)

    existing = db.get_pubkey(req.user_id)
    if existing and not allow_override:
        # Trong safe mode, chỉ chủ sở hữu mới được update key
        # Nhưng trong sandbox đơn giản, cho phép re-register cùng user
        pass

    db.register_key(req.user_id, req.public_key_pem, req.key_bits, req.e, req.fingerprint)
    logger.info(f"[KEY] {req.user_id} registered (bits={req.key_bits}, e={req.e})")

    # Notify monitors
    await manager.broadcast_to_monitors({
        "type": "key_register", "user_id": req.user_id,
        "key_bits": req.key_bits, "e": req.e,
        "fingerprint": req.fingerprint, "timestamp": int(time.time()),
    })

    return {"status": "ok", "user_id": req.user_id}


@app.get("/pubkey/{user_id}")
async def get_pubkey(user_id: str):
    key = db.get_pubkey(user_id)
    if not key:
        raise HTTPException(404, f"User {user_id} không có public key")
    return {
        "user_id": key["user_id"],
        "public_key_pem": key["public_key"],
        "key_bits": key["key_bits"],
        "e": int(key["e_value"]),
        "fingerprint": key["fingerprint"],
    }


@app.get("/pubkeys")
async def get_all_pubkeys():
    keys = db.get_all_pubkeys()
    return {
        "keys": [{
            "user_id": k["user_id"],
            "public_key_pem": k["public_key"],
            "key_bits": k["key_bits"],
            "e": int(k["e_value"]),
            "fingerprint": k["fingerprint"],
        } for k in keys]
    }


@app.delete("/pubkey/{user_id}")
async def delete_pubkey(user_id: str):
    db.delete_pubkey(user_id)
    return {"status": "ok", "user_id": user_id}


# ── Messaging ──

@app.post("/message")
async def send_message(req: MessageRequest):
    profile_name = db.get_config("active_profile", "safe")

    # Nonce check
    if req.nonce:
        if not db.check_nonce(req.nonce):
            return JSONResponse(status_code=400, content={
                "error": {"code": "NONCE_ALREADY_USED",
                          "message": "Nonce đã được sử dụng — phát hiện Replay Attack"}
            })

    # Store message
    import uuid
    msg_id = str(uuid.uuid4())
    db.store_message(msg_id, req.sender, req.to, req.ciphertext,
                     req.plaintext, req.padding_scheme,
                     int(time.time()), req.nonce)

    msg_data = {
        "type": "message", "id": msg_id,
        "from": req.sender, "to": req.to,
        "ciphertext": req.ciphertext,
        "padding_scheme": req.padding_scheme,
        "key_fingerprint": req.key_fingerprint,
        "nonce": req.nonce,
        "timestamp": int(time.time()),
    }

    # Forward to receiver via WebSocket
    await manager.send_to_user(req.to, msg_data)

    # Mirror to all monitors (Eve)
    mirror_data = {
        "type": "traffic_mirror", "id": str(uuid.uuid4()),
        "original_packet_id": msg_id,
        "captured_at": int(time.time()),
        "direction": f"{req.sender} -> {req.to}",
        "raw_packet": msg_data,
        "plaintext_hint": req.plaintext,
    }
    await manager.broadcast_to_monitors(mirror_data)

    logger.info(f"[MSG] {req.sender} -> {req.to} (len={len(req.ciphertext)})")
    return {"status": "ok", "id": msg_id}


@app.get("/messages/{user_id}")
async def get_messages(user_id: str):
    msgs = db.get_messages_for(user_id)
    return {"messages": msgs}


# ── Monitoring ──

@app.get("/traffic/history")
async def traffic_history():
    msgs = db.get_all_messages()
    return {"traffic": msgs}


# ── Admin ──

@app.post("/admin/profile")
async def set_profile(req: ProfileRequest):
    try:
        profile = get_profile(req.profile)
    except ValueError as ex:
        raise HTTPException(400, str(ex))

    db.set_config("active_profile", req.profile)
    logger.info(f"[ADMIN] Profile changed to: {req.profile}")

    # Clear existing keys so nodes regenerate
    db.clear_all_keys()

    # Notify all connected nodes to regenerate keys
    await manager.broadcast_to_all_users({
        "type": "profile_change",
        "profile": req.profile,
        "config": profile,
        "timestamp": int(time.time()),
    })

    # Notify monitors
    await manager.broadcast_to_monitors({
        "type": "profile_change",
        "profile": req.profile,
        "config": profile,
        "timestamp": int(time.time()),
    })

    return {"status": "ok", "profile": req.profile, "config": profile}


@app.get("/admin/status")
async def system_status():
    profile_name = db.get_config("active_profile", "safe")
    profile = get_profile(profile_name)
    keys = db.get_all_pubkeys()
    return {
        "active_profile": profile_name,
        "profile_config": profile,
        "registered_users": [k["user_id"] for k in keys],
        "online_users": manager.get_online_users(),
        "total_messages": len(db.get_all_messages()),
        "timestamp": int(time.time()),
    }


@app.post("/admin/reset")
async def reset_system():
    db.reset_all()
    await manager.broadcast_to_all_users({
        "type": "profile_change", "profile": "safe",
        "config": get_profile("safe"), "timestamp": int(time.time()),
    })
    logger.info("[ADMIN] System reset to defaults")
    return {"status": "ok", "message": "System reset to safe profile"}


@app.get("/admin/profiles")
async def get_profiles():
    return {"profiles": list_profiles(), "all": PROFILES}


@app.get("/admin/attack_results")
async def get_attack_results():
    return {"results": db.get_attack_results()}


@app.post("/admin/attack_result")
async def store_attack_result(data: dict):
    db.store_attack_result(
        data.get("attack_name", ""),
        data.get("profile", ""),
        data.get("success", False),
        json.dumps(data.get("recovered", {})),
        data.get("duration_ms", 0),
        json.dumps(data.get("details", {})),
    )
    return {"status": "ok"}


# ── Decrypt Oracle (for CCA and Bleichenbacher) ──

@app.post("/oracle/decrypt")
async def decrypt_oracle(data: dict):
    """Padding/decryption oracle — chỉ hoạt động khi profile cho phép."""
    profile_name = db.get_config("active_profile", "safe")
    profile = get_profile(profile_name)

    if not profile.get("expose_padding_error") and not profile.get("expose_raw_decrypt"):
        raise HTTPException(403, "Oracle không khả dụng trong profile hiện tại")

    target_user = data.get("target_user", "")
    ciphertext_hex = data.get("ciphertext", "")

    key_data = db.get_pubkey(target_user)
    if not key_data:
        raise HTTPException(404, f"Không tìm thấy key cho {target_user}")

    # Trong thực tế, oracle sẽ decrypt bằng private key của target
    # Ở đây ta trả về response mô phỏng
    return {"oracle_response": "simulated", "profile": profile_name}


# ── WebSocket Endpoints ──
# IMPORTANT: /ws/monitor must be declared BEFORE /ws/{user_id}
# to prevent "monitor" being captured as a user_id parameter

@app.websocket("/ws/monitor")
async def websocket_monitor(ws: WebSocket):
    await manager.connect_monitor(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect_monitor(ws)


@app.websocket("/ws/{user_id}")
async def websocket_user(ws: WebSocket, user_id: str):
    await manager.connect_user(user_id, ws)
    try:
        while True:
            data = await ws.receive_text()
            # Handle client messages if needed
            pass
    except WebSocketDisconnect:
        manager.disconnect_user(user_id)


# ── Online Users ──

@app.get("/online")
async def online_users():
    return {"users": manager.get_online_users()}

