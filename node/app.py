"""
User Node — Client node cho Alice/Bob/Charlie.
Tự động sinh khóa, đăng ký lên Router, giao diện chat.
"""
import os
import sys
import json
import time
import asyncio
import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import requests
import websockets

sys.path.insert(0, "/app/shared")
from crypto_utils import generate_rsa_keypair, encrypt, decrypt, key_fingerprint, pem_to_components, truncate_number, decrypt_with_padding_oracle, raw_decrypt
from protocol import build_message_packet, generate_nonce
from profiles import get_profile, get_profile_key_params

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("node")

NODE_NAME = os.environ.get("NODE_NAME", "alice")
ROUTER_URL = os.environ.get("ROUTER_URL", "http://router:5000")
NODE_PORT = int(os.environ.get("NODE_PORT", "3000"))

# ── State ──
node_state = {
    "name": NODE_NAME,
    "keypair": None,
    "profile": "safe",
    "messages": [],
    "alerts": [],
}

templates = Jinja2Templates(directory="/app/templates")


def generate_and_register_keys(profile_name="safe"):
    """Sinh khóa RSA theo profile và đăng ký lên Router."""
    try:
        params = get_profile_key_params(profile_name)
        logger.info(f"[{NODE_NAME}] Generating keys: {params}")

        keypair = generate_rsa_keypair(
            key_bits=params["key_bits"],
            e=params["e"],
            prime_gap=params.get("prime_gap", "normal"),
        )
        node_state["keypair"] = keypair
        node_state["profile"] = profile_name

        # Đăng ký lên Router
        resp = requests.post(f"{ROUTER_URL}/register", json={
            "user_id": NODE_NAME,
            "public_key_pem": keypair["pem_public"],
            "key_bits": keypair["key_bits"],
            "e": keypair["e"],
            "fingerprint": keypair["fingerprint"],
        }, timeout=10)
        logger.info(f"[{NODE_NAME}] Registered: {resp.status_code}")
        return True
    except Exception as ex:
        logger.error(f"[{NODE_NAME}] Key generation failed: {ex}")
        return False


def start_ws_listener():
    """Background thread để lắng nghe tin nhắn qua WebSocket."""
    async def listen():
        while True:
            try:
                uri = f"ws://router:5000/ws/{NODE_NAME}"
                async with websockets.connect(uri) as ws:
                    logger.info(f"[{NODE_NAME}] WebSocket connected to Router")
                    while True:
                        raw = await ws.recv()
                        data = json.loads(raw)
                        handle_incoming(data)
            except Exception as ex:
                logger.warning(f"[{NODE_NAME}] WS reconnecting in 3s: {ex}")
                await asyncio.sleep(3)

    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(listen())

    t = threading.Thread(target=run, daemon=True)
    t.start()


def handle_incoming(data):
    """Xử lý gói tin nhận được qua WebSocket."""
    msg_type = data.get("type", "")

    if msg_type == "message":
        try:
            ct_hex = data.get("ciphertext", "")
            ct_bytes = bytes.fromhex(ct_hex)
            padding = data.get("padding_scheme", "OAEP")
            kp = node_state.get("keypair")
            if kp:
                pt = decrypt(ct_bytes, kp["pem_private"], padding)
                data["_decrypted"] = pt.decode("utf-8", errors="replace")
            else:
                data["_decrypted"] = "[Không có private key]"
        except Exception as ex:
            data["_decrypted"] = f"[Lỗi giải mã: {ex}]"
            node_state["alerts"].append({
                "type": "decrypt_error", "message": str(ex),
                "timestamp": int(time.time()),
            })
        node_state["messages"].append(data)
        logger.info(f"[{NODE_NAME}] Received message from {data.get('from')}")

    elif msg_type == "profile_change":
        new_profile = data.get("profile", "safe")
        logger.info(f"[{NODE_NAME}] Profile change: {new_profile}")
        generate_and_register_keys(new_profile)

    elif msg_type == "key_compromised":
        node_state["alerts"].append({
            "type": "key_compromised",
            "message": f"⚠ Private Key đã bị lộ! d = {data.get('d', '?')}",
            "attacker": data.get("attacker", "eve"),
            "timestamp": int(time.time()),
        })


# ── App ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Đợi Router sẵn sàng
    for _ in range(30):
        try:
            r = requests.get(f"{ROUTER_URL}/health", timeout=2)
            if r.status_code == 200:
                break
        except:
            pass
        time.sleep(1)

    generate_and_register_keys("safe")
    start_ws_listener()
    yield

app = FastAPI(title=f"Node {NODE_NAME}", lifespan=lifespan)


class SendMessageRequest(BaseModel):
    to: str
    plaintext: str


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("chat.html", {
        "request": request, "node_name": NODE_NAME,
    })


@app.get("/api/state")
async def get_state():
    kp = node_state.get("keypair", {})
    return {
        "name": NODE_NAME,
        "profile": node_state["profile"],
        "has_keys": kp is not None,
        "key_info": {
            "n": truncate_number(kp["n"]) if kp else "",
            "e": kp.get("e", "") if kp else "",
            "d": truncate_number(kp["d"]) if kp else "",
            "key_bits": kp.get("key_bits", 0) if kp else 0,
            "fingerprint": kp.get("fingerprint", "")[:16] if kp else "",
        } if kp else {},
        "padding": get_profile_key_params(node_state["profile"]).get("padding", "OAEP"),
        "messages": node_state["messages"][-50:],
        "alerts": node_state["alerts"][-10:],
    }


@app.get("/api/contacts")
async def get_contacts():
    try:
        r = requests.get(f"{ROUTER_URL}/online", timeout=5)
        online = r.json().get("users", [])
    except:
        online = []
    try:
        r = requests.get(f"{ROUTER_URL}/pubkeys", timeout=5)
        registered = [k["user_id"] for k in r.json().get("keys", [])]
    except:
        registered = []
    contacts = [u for u in registered if u != NODE_NAME]
    return {"contacts": contacts, "online": online}


@app.post("/api/send")
async def send_message(req: SendMessageRequest):
    try:
        # Lấy public key của người nhận
        r = requests.get(f"{ROUTER_URL}/pubkey/{req.to}", timeout=5)
        if r.status_code != 200:
            return JSONResponse(status_code=404, content={"error": f"Không tìm thấy {req.to}"})

        recipient_key = r.json()["public_key_pem"]
        padding = get_profile_key_params(node_state["profile"]).get("padding", "OAEP")

        # Mã hóa
        ct_bytes = encrypt(req.plaintext.encode("utf-8"), recipient_key, padding)
        ct_hex = ct_bytes.hex()

        # Gửi qua Router
        nonce = generate_nonce()
        resp = requests.post(f"{ROUTER_URL}/message", json={
            "sender": NODE_NAME, "to": req.to,
            "ciphertext": ct_hex, "padding_scheme": padding,
            "key_fingerprint": key_fingerprint(recipient_key),
            "nonce": nonce, "plaintext": req.plaintext,
        }, timeout=10)

        if resp.status_code == 200:
            # Lưu tin nhắn đã gửi vào state
            node_state["messages"].append({
                "type": "message", "from": NODE_NAME, "to": req.to,
                "ciphertext": ct_hex[:64] + "...",
                "_decrypted": req.plaintext,
                "timestamp": int(time.time()), "sent": True,
            })
            return {"status": "ok", "ciphertext_preview": ct_hex[:64]}
        else:
            return JSONResponse(status_code=resp.status_code,
                                content=resp.json())

    except Exception as ex:
        return JSONResponse(status_code=500, content={"error": str(ex)})


class OracleRequest(BaseModel):
    ciphertext: str
    type: str # "padding" or "decrypt"

@app.post("/api/oracle")
async def oracle_endpoint(req: OracleRequest):
    profile_name = node_state["profile"]
    profile = get_profile(profile_name)
    kp = node_state["keypair"]
    if not kp:
        return JSONResponse(status_code=400, content={"error": "Node chưa có key"})
    
    ct_bytes = bytes.fromhex(req.ciphertext)
    
    if req.type == "padding" and profile.get("expose_padding_error"):
        res = decrypt_with_padding_oracle(ct_bytes, kp["pem_private"], expose_padding_error=True)
        return {"valid_padding": res.get("success", False), "detail": res.get("detail", "")}
    
    elif req.type == "decrypt" and profile.get("expose_raw_decrypt"):
        c_int = int.from_bytes(ct_bytes, "big")
        m_int = raw_decrypt(c_int, kp["d"], kp["n"])
        return {"plaintext_int": str(m_int)}
        
    return JSONResponse(status_code=403, content={"error": "Oracle không khả dụng trong profile hiện tại"})


@app.post("/api/clear_alerts")
async def clear_alerts():
    node_state["alerts"] = []
    return {"status": "ok"}


@app.get("/api/messages")
async def get_messages():
    return {"messages": node_state["messages"][-50:]}
