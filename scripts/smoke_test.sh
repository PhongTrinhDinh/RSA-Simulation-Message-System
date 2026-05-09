#!/bin/bash
# scripts/smoke_test.sh — Kiểm tra nhanh hệ thống sau docker compose up

PASS=0; FAIL=0

check() {
    local desc=$1; local cmd=$2
    if eval "$cmd" &>/dev/null; then
        echo "  ✅ $desc"; ((PASS++))
    else
        echo "  ❌ $desc"; ((FAIL++))
    fi
}

echo "═══════════════════════════════════════════"
echo "  RSA OTT Sandbox — Smoke Test"
echo "═══════════════════════════════════════════"

echo "── Router API ─────────────────────────────"
check "Router health"         "curl -sf http://localhost:5000/health"
check "GET /pubkeys"          "curl -sf http://localhost:5000/pubkeys"
check "GET /admin/status"     "curl -sf http://localhost:5000/admin/status"

echo "── Node Registration ──────────────────────"
check "Alice registered"   "curl -sf http://localhost:5000/pubkey/alice"
check "Bob registered"     "curl -sf http://localhost:5000/pubkey/bob"
check "Charlie registered" "curl -sf http://localhost:5000/pubkey/charlie"

echo "── Dashboards ──────────────────────────────"
check "Alice dashboard"     "curl -sf http://localhost:3001"
check "Bob dashboard"       "curl -sf http://localhost:3002"
check "Charlie dashboard"   "curl -sf http://localhost:3003"
check "Eve dashboard"       "curl -sf http://localhost:3000"

echo "── Attack Modules ─────────────────────────"
check "Wiener module"         "docker exec eve python3 -c 'from attacks.wiener import wiener_attack; print(\"ok\")'"
check "Hastad module"         "docker exec eve python3 -c 'from attacks.hastad import hastad_attack; print(\"ok\")'"
check "Common modulus module" "docker exec eve python3 -c 'from attacks.common_modulus import common_modulus_attack; print(\"ok\")'"
check "Factor module"         "docker exec eve python3 -c 'from attacks.factor_n import fermat_factorization; print(\"ok\")'"
check "Brute force module"    "docker exec eve python3 -c 'from attacks.brute_force import brute_force_attack; print(\"ok\")'"

echo "═══════════════════════════════════════════"
echo "  PASSED: $PASS  |  FAILED: $FAIL"
echo "═══════════════════════════════════════════"
[ $FAIL -eq 0 ] && exit 0 || exit 1
