"""
Eve (Attacker Node) — Dashboard giám sát và tấn công.
"""
import os
import sys
import json
import time
import asyncio
import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import requests
import websockets

sys.path.insert(0, "/app/shared")
from crypto_utils import (generate_rsa_keypair, encrypt, decrypt, raw_decrypt,
                          pem_to_components, decrypt_with_padding_oracle)
from profiles import get_profile, list_profiles, get_profile_key_params, PROFILES
from attacks import (brute_force_attack, fermat_factorization, pollard_rho, cca_attack)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("eve")

ROUTER_URL = os.environ.get("ROUTER_URL", "http://router:5000")

# ── State ──
eve_state = {
    "traffic": [],
    "keypair": None,
    "profile": "safe",
    "attack_results": [],
}

templates = Jinja2Templates(directory="/app/templates")


def start_monitor():
    """Background: subscribe Router /ws/monitor để nhận mirror traffic."""
    async def listen():
        while True:
            try:
                async with websockets.connect(f"ws://router:5000/ws/monitor") as ws:
                    logger.info("[EVE] Monitor connected")
                    while True:
                        raw = await ws.recv()
                        data = json.loads(raw)
                        eve_state["traffic"].append(data)
                        if len(eve_state["traffic"]) > 500:
                            eve_state["traffic"] = eve_state["traffic"][-500:]
            except Exception as ex:
                logger.warning(f"[EVE] Monitor reconnecting: {ex}")
                await asyncio.sleep(3)

    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(listen())

    threading.Thread(target=run, daemon=True).start()


@asynccontextmanager
async def lifespan(app: FastAPI):
    for _ in range(30):
        try:
            r = requests.get(f"{ROUTER_URL}/health", timeout=2)
            if r.status_code == 200:
                break
        except:
            pass
        time.sleep(1)

    # Eve cũng tạo keypair riêng
    kp = generate_rsa_keypair(key_bits=1024, e=65537)
    eve_state["keypair"] = kp
    start_monitor()
    yield

app = FastAPI(title="Eve — Attacker Dashboard", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("attacker.html", {"request": request})


@app.get("/api/state")
async def get_state():
    try:
        r = requests.get(f"{ROUTER_URL}/admin/status", timeout=5)
        system = r.json()
    except:
        system = {}
    return {
        "profile": system.get("active_profile", "unknown"),
        "system": system,
        "traffic_count": len(eve_state["traffic"]),
        "attack_results": eve_state["attack_results"][-20:],
    }


@app.get("/api/traffic")
async def get_traffic():
    return {"traffic": eve_state["traffic"][-100:]}


@app.get("/api/profiles")
async def get_profiles():
    return {"profiles": list_profiles(), "all": PROFILES}


class SetProfileRequest(BaseModel):
    profile: str

@app.post("/api/set_profile")
async def set_profile(req: SetProfileRequest):
    try:
        r = requests.post(f"{ROUTER_URL}/admin/profile",
                          json={"profile": req.profile}, timeout=10)
        eve_state["profile"] = req.profile
        return r.json()
    except Exception as ex:
        return JSONResponse(status_code=500, content={"error": str(ex)})


class AttackRequest(BaseModel):
    attack: str
    target_user: str = "bob"
    params: dict = {}

@app.post("/api/attack")
async def run_attack(req: AttackRequest):
    """Chạy attack module và trả về kết quả."""
    start = time.time()
    result = {"attack": req.attack, "success": False}

    try:
        # Lấy thông tin hệ thống
        sys_r = requests.get(f"{ROUTER_URL}/admin/status", timeout=5)
        system = sys_r.json()
        
        # Lấy public key target
        key_r = requests.get(f"{ROUTER_URL}/pubkey/{req.target_user}", timeout=5)
        target_key = key_r.json() if key_r.status_code == 200 else {}
        target_n = 0
        target_e = int(target_key.get("e", 65537))

        if target_key.get("public_key_pem"):
            comps = pem_to_components(target_key["public_key_pem"])
            target_n = comps["n"]
            target_e = comps["e"]

        # Lấy ciphertext từ traffic
        ciphertexts_for_target = [
            t for t in eve_state["traffic"]
            if t.get("type") == "traffic_mirror"
            and t.get("raw_packet", {}).get("to") == req.target_user
        ]

        if req.attack == "brute_force":
            if not target_n:
                result["error"] = "Không có public key của target"
            else:
                ct_int = None
                if ciphertexts_for_target:
                    ct_hex = ciphertexts_for_target[-1]["raw_packet"]["ciphertext"]
                    ct_int = int(ct_hex, 16)
                result = brute_force_attack(target_n, target_e, ct_int)
                result["attack"] = "brute_force"

        elif req.attack == "factor_n":
            method = req.params.get("method", "fermat")
            if method == "fermat":
                result = fermat_factorization(target_n)
            else:
                result = pollard_rho(target_n)
            result["attack"] = "factor_n"
            # Nếu thành công, tính d và giải mã
            if result.get("success") and ciphertexts_for_target:
                p, q = result["p"], result["q"]
                from Crypto.Util.number import inverse
                phi_n = (p-1)*(q-1)
                d = int(inverse(target_e, phi_n))
                result["d"] = d
                ct_hex = ciphertexts_for_target[-1]["raw_packet"]["ciphertext"]
                ct_int = int(ct_hex, 16)
                m = pow(ct_int, d, target_n)
                try:
                    result["plaintext"] = m.to_bytes((m.bit_length()+7)//8, 'big').decode('utf-8', errors='replace')
                except:
                    result["plaintext"] = str(m)

        elif req.attack == "cca":
            if ciphertexts_for_target:
                ct_hex = ciphertexts_for_target[-1]["raw_packet"]["ciphertext"]
                ct_int = int(ct_hex, 16)

                def oracle_fn(c):
                    try:
                        r = requests.post(f"http://{req.target_user}:3000/api/oracle", json={
                            "ciphertext": hex(c)[2:],
                            "type": "decrypt"
                        }, timeout=5)
                        if r.status_code == 200:
                            return int(r.json().get("plaintext_int", 0))
                    except:
                        pass
                    return None

                result = cca_attack(ct_int, target_e, target_n, oracle_fn)
            else:
                result = {"success": False, "error": "Không có ciphertext"}
            result["attack"] = "cca"

        else:
            result = {"success": False, "error": f"Attack không hợp lệ hoặc đã bị loại bỏ: {req.attack}"}

    except Exception as ex:
        result["error"] = str(ex)
        logger.error(f"Attack {req.attack} failed: {ex}", exc_info=True)

    result["duration_ms"] = int((time.time() - start) * 1000)
    eve_state["attack_results"].append(result)

    # Lưu kết quả lên Router
    try:
        requests.post(f"{ROUTER_URL}/admin/attack_result", json={
            "attack_name": req.attack, "profile": eve_state.get("profile", ""),
            "success": result.get("success", False),
            "recovered": {k: str(v) for k, v in result.items()
                          if k in ["d", "p", "q", "plaintext"]},
            "duration_ms": result.get("duration_ms", 0),
        }, timeout=5)
    except:
        pass

    return result


@app.post("/api/reset")
async def reset():
    try:
        r = requests.post(f"{ROUTER_URL}/admin/reset", timeout=5)
        eve_state["traffic"] = []
        eve_state["attack_results"] = []
        return r.json()
    except Exception as ex:
        return JSONResponse(status_code=500, content={"error": str(ex)})
