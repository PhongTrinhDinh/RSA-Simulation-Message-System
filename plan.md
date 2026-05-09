# Kế hoạch Xây dựng Sandbox Kiểm thử Tấn công Hệ thống Tin nhắn OTT

Tài liệu này mô tả chi tiết kế hoạch xây dựng một môi trường giả lập (sandbox) dựa trên Docker, phục vụ mục đích kiểm thử và nghiên cứu các kỹ thuật tấn công mã hóa và giao thức mạng trên một hệ thống tin nhắn OTT.

---

## 1. Tổng quan Kiến trúc Hệ thống

- **Mô hình Mạng**: Hệ thống hoạt động theo mô hình **Client - Router - Client**. Một Central Server (đóng vai trò Router/Key Server) quản lý trạng thái online, lưu trữ Public Key Directory và định tuyến tin nhắn, nhưng **không giữ khóa bí mật của người dùng**.
- **Backend (Nodes & Server)**: Xây dựng bằng Python (FastAPI hoặc Flask) hỗ trợ WebSocket để truyền tin nhắn theo thời gian thực. Python là lựa chọn tối ưu nhờ hệ sinh thái thư viện toán học và mật mã phong phú (`PyCryptodome`, `gmpy2`, `sympy`).
- **Frontend (Dashboard)**: Xây dựng bằng **HTML/JS thuần kết hợp htmx**, cung cấp giao diện Web trực quan cho từng Node (người dùng) và màn hình giám sát dành cho Kẻ tấn công (Attacker). Lựa chọn này loại bỏ sự phức tạp của build pipeline (không cần npm, webpack), giảm overhead triển khai và phù hợp với môi trường sandbox giáo dục. Lưu ý giao diện phải dễ nhìn, dễ sử dụng, màu sắc hài hòa.
- **Môi trường Triển khai**: 100% container hóa sử dụng **Docker & Docker Compose** để giả lập nhiều nodes mạng giao tiếp với nhau trong một mạng cục bộ (Docker Network).

### 1.1. Cơ chế Trao đổi Khóa Công khai

Khi một Node khởi động, nó tạo cặp khóa RSA cục bộ và đăng ký Public Key lên Router thông qua endpoint `/register`. Router lưu trữ Public Key Directory này và phục vụ các node khác truy vấn. **Router không thực hiện bất kỳ xác thực nào đối với public key được đăng ký** — đây là lỗ hổng cố ý để cho phép thực hiện MITM Attack.

Luồng trao đổi khóa:

```
Alice khởi động → POST /register {user: "alice", pubkey: ...}
Alice muốn nhắn Bob → GET /pubkey/bob → nhận public key của Bob
Alice mã hóa msg bằng pubkey Bob → gửi qua Router → Bob nhận & giải mã
```

---

## 2. Thiết kế Môi trường Giả lập (Docker Environment)

### 2.1. Các Container

Môi trường Docker bao gồm các container sau:

- **Server Container (`router`)**: Trung tâm định tuyến tin nhắn, cung cấp Public Key Directory, mirror traffic đến Eve, và hỗ trợ các chế độ lỗ hổng có thể bật/tắt.
- **User Node Containers (`alice`, `bob`, `charlie`)**: Giả lập người dùng hợp lệ. Mỗi node có cặp khóa riêng, giao diện Chat và hoạt động độc lập với nhau.
- **Attacker Node Container (`eve`)**: Node đặc quyền, nhận mirror traffic từ Router, tích hợp sẵn các tool tấn công và môi trường Jupyter Lab.
- **Mạng**: `sandbox-net` (bridge network trong Docker) cho phép các container giao tiếp theo hostname.

### 2.2. Chiến lược Traffic Interception (Mirror qua Router)

Trong Docker bridge network, unicast traffic chỉ đến đúng destination container — Eve không thể tự động thấy traffic giữa Alice và Bob. Để giải quyết vấn đề này, **Router chủ động mirror (nhân bản) toàn bộ gói tin qua một kênh riêng đến Eve**.

Cơ chế hoạt động:

```
Alice gửi msg cho Bob:
  1. Alice → POST /message → Router
  2. Router forward msg đến Bob (destination)
  3. Router đồng thời mirror toàn bộ payload đến Eve
     qua WebSocket channel /ws/monitor (realtime)
     hoặc POST /mirror (push từng gói)
  4. Eve nhận được bản sao ciphertext mà không cần
     can thiệp vào đường truyền Alice-Bob
```

Lưu ý: Đây là simplification so với passive sniffing thực tế (promiscuous mode ở L2). Trong sandbox, Router đóng vai trò "điểm quan sát tập trung" thay vì Eve phải thực hiện ARP spoofing. Cơ chế này đủ để demo tất cả các crypto attack (Wiener, Håstad, Bleichenbacher...) vì các attack đó chỉ cần có ciphertext, không yêu cầu passive capture.

### 2.3. Router API Endpoints

Router cung cấp đầy đủ các endpoint sau:

**Public Key Directory:**

| Method | Endpoint | Mô tả |
|---|---|---|
| `POST` | `/register` | Node đăng ký public key khi khởi động |
| `GET` | `/pubkey/{user}` | Lấy public key của một user cụ thể |
| `GET` | `/pubkeys` | Lấy toàn bộ Public Key Directory |
| `DELETE` | `/pubkey/{user}` | Hủy đăng ký (khi node offline) |

**Messaging:**

| Method | Endpoint | Mô tả |
|---|---|---|
| `POST` | `/message` | Gửi tin nhắn đã mã hóa từ sender đến receiver |
| `GET` | `/messages/{user}` | Lấy danh sách tin nhắn chờ của một user |
| `WebSocket` | `/ws/{user}` | Kết nối realtime nhận tin nhắn |

**Monitoring (Eve):**

| Method | Endpoint | Mô tả |
|---|---|---|
| `WebSocket` | `/ws/monitor` | Stream toàn bộ traffic realtime đến Eve |
| `GET` | `/traffic/history` | Lấy lịch sử các gói tin đã đi qua Router |

**Administration:**

| Method | Endpoint | Mô tả |
|---|---|---|
| `POST` | `/admin/profile` | Kích hoạt Attack Profile (xem Mục 4) |
| `GET` | `/admin/status` | Trạng thái hệ thống và profile đang dùng |
| `POST` | `/admin/reset` | Reset toàn bộ keys, messages, profile về mặc định |

---

## 3. Các Kịch bản Tấn công (Attack Scenarios)

Hệ thống hỗ trợ và minh họa các cuộc tấn công sau:

1. **Brute Force**: Tấn công vét cạn không gian khóa đối với các cấu hình có độ dài khóa cực kỳ nhỏ (demo lý thuyết về độ phức tạp tính toán).
2. **Factor n (Phân tích thừa số)**: Khai thác module `n` được tạo từ số nguyên tố `p`, `q` yếu bằng Fermat's Factorization hoặc Pollard's Rho.
3. **MITM Attack (Man-in-the-Middle)**: Khai thác việc Router không xác thực public key — Eve thay thế public key của Bob bằng public key của mình trong Directory, từ đó Alice vô tình mã hóa tin nhắn bằng khóa của Eve.
4. **CCA Oracle (Chosen-Ciphertext Attack)**: Khai thác việc Server/Node trả về thông báo lỗi khi nhận được bản mã không hợp lệ, từ đó dò ra bản rõ bằng tính nhân tính của RSA.
5. **Bleichenbacher's Attack**: Một dạng Padding Oracle Attack nhắm vào chuẩn padding RSA PKCS#1 v1.5, gửi hàng loạt requests để khôi phục session key thông qua phản hồi lỗi padding từ server.
6. **Wiener's Attack**: Khai thác lỗ hổng khi khóa bí mật `d` được chọn quá nhỏ (`d < (1/3)*N^(1/4)`), sử dụng khai triển liên phân số (continued fraction) để phục hồi `d`.
7. **Håstad's Broadcast Attack**: Bắt gói tin khi cùng một tin nhắn được mã hóa gửi cho nhiều người dùng với số mũ công khai nhỏ (ví dụ `e=3`), dùng Định lý Thặng dư Trung Hoa (CRT) để khôi phục bản rõ.
8. **Common Modulus Attack**: Khai thác lỗ hổng khi nhiều người dùng dùng chung module `n` nhưng khác số mũ `e`. Nếu `gcd(e1, e2) = 1`, bắt được hai bản mã của cùng một tin nhắn là đủ để giải mã hoàn toàn.

---

## 4. Xây dựng Cấu hình Tấn công (Profiles & Configuration)

Hệ thống cung cấp cơ chế **Attack Profile** để kích hoạt nhanh các trạng thái lỗ hổng khác nhau. Người dùng chọn một profile từ giao diện — không cấu hình thủ công từng tham số — để tránh sai sót và đơn giản hóa quá trình demo.

### 4.1. Danh sách Attack Profiles

```json
{
  "profiles": {

    "safe": {
      "description": "Hệ thống an toàn — RSA chuẩn, không có lỗ hổng",
      "key_bits": 2048,
      "e": 65537,
      "padding": "OAEP",
      "common_modulus": false,
      "expose_padding_error": false,
      "allow_pubkey_override": false
    },

    "brute_force_demo": {
      "description": "Key cực nhỏ để minh họa brute force về lý thuyết",
      "key_bits": 32,
      "e": 17,
      "padding": "none",
      "note": "Chỉ mang ý nghĩa minh họa độ phức tạp O(2^k)"
    },

    "factor_n_vulnerable": {
      "description": "p và q gần nhau — Fermat Factorization khả thi",
      "key_bits": 512,
      "prime_gap": "small",
      "e": 65537,
      "padding": "PKCS1_v1.5"
    },

    "mitm_vulnerable": {
      "description": "Router không xác thực public key — MITM dễ dàng",
      "key_bits": 1024,
      "e": 65537,
      "padding": "PKCS1_v1.5",
      "allow_pubkey_override": true,
      "verify_pubkey_signature": false
    },

    "cca_vulnerable": {
      "description": "Textbook RSA không có padding — CCA trực tiếp",
      "key_bits": 1024,
      "e": 65537,
      "padding": "none",
      "expose_raw_decrypt": true
    },

    "bleichenbacher_vulnerable": {
      "description": "PKCS#1 v1.5 với padding oracle rõ ràng",
      "key_bits": 1024,
      "e": 65537,
      "padding": "PKCS1_v1.5",
      "expose_padding_error": true,
      "error_message": "distinct"
    },

    "wiener_vulnerable": {
      "description": "d nhỏ hơn ngưỡng Wiener — liên phân số tìm được d",
      "key_bits": 1024,
      "force_small_d": true,
      "d_bits": 60,
      "padding": "PKCS1_v1.5"
    },

    "hastad_vulnerable": {
      "description": "e=3, broadcast cùng message cho 3+ users",
      "key_bits": 1024,
      "e": 3,
      "padding": "none",
      "broadcast_mode": true,
      "min_recipients": 3
    },

    "common_modulus_vulnerable": {
      "description": "Tất cả users dùng chung modulus n, e khác nhau",
      "shared_modulus": true,
      "e_list": [65537, 257, 17],
      "padding": "PKCS1_v1.5"
    }

  }
}
```

### 4.2. Cơ chế Áp dụng Profile

Khi admin (hoặc Eve) gọi `POST /admin/profile` với `{"profile": "wiener_vulnerable"}`:

1. Router tải cấu hình profile tương ứng.
2. Router gửi tín hiệu đến tất cả Node để tái tạo cặp khóa theo tham số mới.
3. Node xóa khóa cũ, sinh khóa mới theo profile, đăng ký lại lên Router.
4. Giao diện Admin hiển thị thông báo xác nhận profile đã được áp dụng.
5. Trạng thái profile hiện tại được lưu vào database để persist qua restart.

---

## 5. Dashboard & Giao diện các Node mạng

Sandbox cung cấp hai loại Dashboard thông qua giao diện Web (HTML/JS + htmx):

### 5.1. User Dashboard (Giao diện người dùng bình thường)

- **Danh sách liên hệ**: Hiển thị các Node đang online với trạng thái kết nối realtime.
- **Giao diện Chat**: Gửi/nhận tin nhắn, cập nhật tức thì qua htmx polling hoặc Server-Sent Events.
- **Song song Plaintext / Ciphertext**: Hiển thị đồng thời nội dung tin nhắn gốc và chuỗi hex ciphertext đang truyền qua mạng, giúp người học thấy rõ dữ liệu bị che giấu như thế nào.
- **Thông số Key**: Hiển thị `n`, `e`, `d` (dạng rút gọn), độ dài key, padding scheme đang sử dụng.
- **Cảnh báo tấn công**: Khi hệ thống phát hiện dấu hiệu bất thường (public key bị thay đổi, nhận được ciphertext không giải mã được...), hiển thị banner cảnh báo màu đỏ kèm giải thích lỗ hổng đang bị khai thác.
- **Trạng thái Key bị Compromise**: Sau khi một attack thành công (ví dụ Wiener tìm được `d`), giao diện User hiển thị thông báo "⚠ Private Key của bạn đã bị lộ" cùng giá trị `d` thực tế mà attacker đã phục hồi.
- **Message Integrity**: Hiển thị rõ rằng RSA thuần túy (không có chữ ký số) không đảm bảo tính toàn vẹn — tin nhắn có thể bị sửa đổi mà người nhận không phát hiện.

### 5.2. Attacker Dashboard (Giao diện Giám sát và Tấn công)

- **Network Traffic Monitor**: Bảng realtime hiển thị các gói tin (ciphertext) đang luân chuyển giữa các node, bao gồm: sender, receiver, timestamp, ciphertext hex, kích thước payload.
- **Profile Selector**: Dropdown chọn Attack Profile (xem Mục 4), áp dụng ngay lên toàn bộ hệ thống mà không cần restart.
- **Attack Arsenal**: Danh sách các nút trigger để khởi chạy từng attack module:
  - Mỗi nút hiển thị tên attack, điều kiện tiên quyết (ví dụ: "Cần profile `wiener_vulnerable`"), và trạng thái khả thi hay không dựa trên profile hiện tại.
  - Sau khi trigger, kết quả (key phục hồi được, plaintext, thời gian thực thi) hiển thị ngay trong panel bên cạnh.
- **Attack Visualizer**: Minh họa trực quan từng bước của quá trình tấn công:
  - **Wiener Attack**: Hiển thị chuỗi các hội tụ (convergents) của khai triển liên phân số `e/n`, highlight convergent tìm được `d` đúng.
  - **Bleichenbacher**: Progress bar số queries đã gửi, đồ thị thu hẹp dần khoảng `[a, b]` chứa plaintext theo từng iteration.
  - **Håstad Broadcast**: Hiển thị 3 ciphertext từ 3 recipients, minh họa bước CRT tổng hợp và phép lấy căn bậc 3 nguyên.
  - **Factor n**: Hiển thị vòng lặp Pollard's Rho với cycle detection, highlight thời điểm tìm ra `p`.
  - **Common Modulus**: Hiển thị bước Extended GCD, giá trị `a`, `b` tìm được, và phép tính `c1^a * c2^b mod n`.
  - **MITM Attack**: Sơ đồ mũi tên minh họa luồng tin nhắn Alice → Eve → Bob, so sánh public key thật vs public key giả mạo.
- **Jupyter Lab Integration**: Truy cập môi trường Jupyter Lab tích hợp sẵn trong Attacker Node tại `http://eve:8888`, cung cấp các hàm tiện ích:
  - `intercept_traffic()` — Lấy danh sách gói tin đã bắt được từ Router.
  - `send_custom_payload(to, ciphertext_hex)` — Gửi payload tùy chỉnh đến một node.
  - `query_padding_oracle(ciphertext_hex)` — Gửi truy vấn đến padding oracle và nhận phản hồi.
  - `run_attack(name, **kwargs)` — Chạy một attack module với tham số tùy chỉnh.

---

## 6. Cấu trúc JSON Message Protocol

Mọi tin nhắn trao đổi trong hệ thống đều tuân theo cấu trúc JSON thống nhất sau:

### 6.1. Gói tin Tin nhắn (Message Packet)

```json
{
  "version": "1.0",
  "id": "uuid-v4-duy-nhat",
  "type": "message",
  "from": "alice",
  "to": "bob",
  "timestamp": 1700000000,
  "nonce": "hex-16-bytes-random",
  "payload": {
    "ciphertext": "hex-encoded-rsa-ciphertext",
    "padding_scheme": "PKCS1_v1.5",
    "key_fingerprint": "sha256-of-pubkey-used"
  },
  "signature": null
}
```

Giải thích các trường:

| Trường | Kiểu | Mô tả |
|---|---|---|
| `version` | string | Phiên bản protocol |
| `id` | string | UUID duy nhất của gói tin, dùng để phát hiện Replay Attack |
| `type` | string | Loại gói: `message`, `key_register`, `ack`, `error` |
| `from` / `to` | string | Định danh sender và receiver |
| `timestamp` | integer | Unix timestamp (giây), phát hiện gói tin cũ |
| `nonce` | string | Giá trị ngẫu nhiên 16 bytes (hex), chống Replay Attack |
| `payload.ciphertext` | string | Bản mã RSA dạng hex |
| `payload.padding_scheme` | string | Padding đang dùng: `OAEP`, `PKCS1_v1.5`, hoặc `none` |
| `payload.key_fingerprint` | string | SHA-256 của public key dùng để mã hóa (phát hiện MITM) |
| `signature` | string / null | Chữ ký số RSA của sender (null nếu profile không bật) |

### 6.2. Gói tin Đăng ký Khóa (Key Register Packet)

```json
{
  "version": "1.0",
  "id": "uuid-v4",
  "type": "key_register",
  "from": "alice",
  "timestamp": 1700000000,
  "payload": {
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
    "key_bits": 1024,
    "e": 65537,
    "fingerprint": "sha256-of-public-key"
  }
}
```

### 6.3. Gói tin Mirror Traffic (Router → Eve)

```json
{
  "version": "1.0",
  "id": "uuid-v4",
  "type": "traffic_mirror",
  "original_packet_id": "uuid-của-gói-gốc",
  "captured_at": 1700000001,
  "direction": "alice -> bob",
  "raw_packet": { "...toàn bộ gói tin gốc..." }
}
```

### 6.4. Gói tin Lỗi (Error Packet)

```json
{
  "version": "1.0",
  "id": "uuid-v4",
  "type": "error",
  "from": "router",
  "to": "alice",
  "timestamp": 1700000000,
  "error": {
    "code": "PADDING_INVALID",
    "message": "RSA decryption failed: padding check error",
    "detail": "PKCS1_v1.5 padding bytes incorrect"
  }
}
```

*Lưu ý: Khi profile `bleichenbacher_vulnerable` được bật, trường `error.code` trả về phân biệt rõ `PADDING_INVALID` vs `DECRYPTION_FAILED` — đây là padding oracle leak cố ý.*

---

## 7. Persistence (Lưu trữ Dữ liệu)

Hệ thống sử dụng **SQLite** làm database mặc định (nhúng trực tiếp trong Router container, không cần container database riêng). SQLite phù hợp với sandbox giáo dục vì đơn giản, không cần cấu hình, và dữ liệu lưu trong một file duy nhất.

### 7.1. Những Gì Cần Persist

| Dữ liệu | Lý do cần persist | Bảng SQLite |
|---|---|---|
| Public Key Directory | Nodes restart không mất key đã đăng ký | `public_keys` |
| Lịch sử tin nhắn | Eve xem lại traffic cũ, debug attack | `messages` |
| Attack Profile đang dùng | Restart không reset về `safe` ngoài ý muốn | `system_config` |
| Kết quả các attack đã chạy | Báo cáo, so sánh nhiều lần chạy | `attack_results` |
| Nonce đã dùng | Phát hiện Replay Attack | `used_nonces` |

### 7.2. Schema Database

```sql
-- Public Key Directory
CREATE TABLE public_keys (
    user_id     TEXT PRIMARY KEY,
    public_key  TEXT NOT NULL,
    key_bits    INTEGER,
    fingerprint TEXT,
    registered_at INTEGER,
    is_active   BOOLEAN DEFAULT TRUE
);

-- Lịch sử gói tin (traffic log)
CREATE TABLE messages (
    id          TEXT PRIMARY KEY,
    sender      TEXT NOT NULL,
    receiver    TEXT NOT NULL,
    ciphertext  TEXT NOT NULL,
    padding     TEXT,
    timestamp   INTEGER NOT NULL,
    nonce       TEXT,
    direction   TEXT
);

-- Cấu hình hệ thống (lưu profile hiện tại)
CREATE TABLE system_config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  INTEGER
);

-- Kết quả tấn công
CREATE TABLE attack_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_name TEXT NOT NULL,
    profile     TEXT,
    success     BOOLEAN,
    recovered   TEXT,
    duration_ms INTEGER,
    ran_at      INTEGER
);

-- Nonce tracking (chống Replay Attack)
CREATE TABLE used_nonces (
    nonce       TEXT PRIMARY KEY,
    used_at     INTEGER NOT NULL
);
```

### 7.3. Chiến lược Mount Volume

```yaml
# docker-compose.yml (đoạn volumes)
services:
  router:
    volumes:
      - ./data/router.db:/app/router.db     # SQLite database
      - ./data/traffic_log:/app/logs        # Raw packet logs (JSON)

  eve:
    volumes:
      - ./data/attack_results:/opt/results  # Kết quả attack scripts
      - ./notebooks:/opt/notebooks          # Jupyter notebooks
```

Toàn bộ dữ liệu persist trong thư mục `./data/` trên host. Để reset hoàn toàn về trạng thái ban đầu: `rm -rf ./data/ && docker compose up`.

---

## 8. Kế hoạch Kiểm thử & Validation

Hệ thống có ba lớp kiểm thử: Unit Test cho từng attack module, Integration Test cho toàn bộ luồng hệ thống, và Smoke Test chạy nhanh khi khởi động.

### 8.1. Unit Test — Từng Attack Module

Mỗi attack module có file test riêng, chạy độc lập không cần Docker.

**Test Wiener's Attack (`tests/test_wiener.py`):**

```python
def test_wiener_recovers_d_when_d_is_small():
    # Tạo keypair với d nhỏ cố ý
    d, p, q = generate_small_d_key(key_bits=512, d_bits=50)
    n = p * q
    e = inverse(d, (p-1)*(q-1))
    # Chạy attack
    result = wiener_attack(e, n)
    assert result is not None
    assert result['d'] == d
    assert result['p'] * result['q'] == n

def test_wiener_fails_when_d_is_large():
    # d đủ lớn → Wiener không tìm được
    key = RSA.generate(1024)
    result = wiener_attack(key.e, key.n)
    assert result is None
```

**Test Håstad Broadcast (`tests/test_hastad.py`):**

```python
def test_hastad_recovers_plaintext_with_e3_and_3_recipients():
    message = b"HASTAD_TEST"
    m_int = int.from_bytes(message, 'big')
    # Tạo 3 keypair với e=3, n khác nhau
    recipients = [gen_rsa_keypair(e=3, bits=512) for _ in range(3)]
    ciphertexts = [pow(m_int, 3, r['n']) for r in recipients]
    ns = [r['n'] for r in recipients]
    # Chạy attack
    recovered_int = hastad_attack(ns, ciphertexts, e=3)
    recovered = recovered_int.to_bytes((recovered_int.bit_length()+7)//8, 'big')
    assert recovered == message

def test_hastad_fails_with_insufficient_recipients():
    # Chỉ 2 recipients với e=3 → không đủ
    with pytest.raises(InsufficientDataError):
        hastad_attack(ns=[n1, n2], ciphertexts=[c1, c2], e=3)
```

**Test Common Modulus (`tests/test_common_modulus.py`):**

```python
def test_common_modulus_recovers_message():
    message = b"COMMON_MOD_SECRET"
    m_int = int.from_bytes(message, 'big')
    # Hai keypair dùng chung n
    n, e1, e2, d1, d2 = gen_common_modulus_keys()
    c1 = pow(m_int, e1, n)
    c2 = pow(m_int, e2, n)
    recovered_int = common_modulus_attack(n, e1, e2, c1, c2)
    recovered = recovered_int.to_bytes((recovered_int.bit_length()+7)//8, 'big')
    assert recovered == message

def test_common_modulus_fails_if_gcd_not_1():
    # gcd(e1, e2) != 1 → attack không áp dụng được
    with pytest.raises(AttackPreconditionError):
        common_modulus_attack(n, e1=6, e2=4, c1=c1, c2=c2)
```

**Test Bleichenbacher (`tests/test_bleichenbacher.py`):**

```python
def test_padding_oracle_returns_distinct_errors():
    # Server phải trả về lỗi phân biệt (padding oracle leak)
    valid_ct = encrypt_pkcs1v15(b"A" * 16, pubkey)
    invalid_ct = os.urandom(128)
    r1 = query_oracle(valid_ct)
    r2 = query_oracle(invalid_ct)
    assert r1['error'] != r2['error'], "Padding oracle phải trả về lỗi khác nhau"

def test_bleichenbacher_recovers_short_message():
    message = b"SECRET"
    ciphertext = encrypt_pkcs1v15(message, pubkey)
    recovered = bleichenbacher_attack(ciphertext, pubkey, oracle_fn=query_oracle)
    assert recovered == message
```

**Test Factor n (`tests/test_factor.py`):**

```python
def test_fermat_factors_close_primes():
    # p và q gần nhau → Fermat Factorization nhanh
    p = sympy.nextprime(2**127)
    q = sympy.nextprime(p)
    n = p * q
    result = fermat_factorization(n)
    assert result['p'] * result['q'] == n
    assert set([result['p'], result['q']]) == set([p, q])

def test_pollard_rho_factors_512bit_n():
    key = RSA.generate(512)
    result = pollard_rho(key.n)
    assert result is not None
    assert result['p'] * result['q'] == key.n
```

**Test MITM Attack (`tests/test_mitm.py`):**

```python
def test_eve_can_override_pubkey_when_profile_allows():
    set_profile("mitm_vulnerable")
    # Eve đăng ký pubkey giả mạo thay cho Bob
    register_pubkey("bob", eve_pubkey)
    fetched = get_pubkey("bob")
    assert fetched == eve_pubkey  # Router chấp nhận override

def test_router_rejects_pubkey_override_in_safe_profile():
    set_profile("safe")
    original = get_pubkey("bob")
    register_pubkey("bob", eve_pubkey)
    assert get_pubkey("bob") == original  # Không bị override
```

### 8.2. Integration Test — Toàn bộ Hệ thống

Chạy sau khi `docker compose up`, kiểm tra end-to-end flow.

```python
# tests/test_integration.py

def test_alice_can_send_message_to_bob():
    """Luồng cơ bản: Alice gửi, Bob nhận, giải mã đúng."""
    set_profile("safe")
    alice_sends("bob", "Hello Bob!")
    messages = bob_inbox()
    assert any(m['plaintext'] == "Hello Bob!" for m in messages)

def test_router_mirrors_all_traffic_to_eve():
    """Mọi gói tin phải xuất hiện trong monitor của Eve."""
    alice_sends("bob", "Secret message")
    eve_traffic = eve_monitor_log()
    assert any("alice" in t['direction'] for t in eve_traffic)

def test_wiener_attack_end_to_end():
    """Kích hoạt profile, Alice gửi msg, Eve chạy attack, giải mã được."""
    set_profile("wiener_vulnerable")
    wait_for_key_regen()
    alice_sends("bob", "wiener target message")
    # Chạy attack qua API
    result = trigger_attack("wiener")
    assert result['success'] is True
    assert 'd' in result['recovered']

def test_hastad_attack_end_to_end():
    set_profile("hastad_vulnerable")
    wait_for_key_regen()
    # Alice broadcast cùng msg cho alice, bob, charlie
    broadcast_message("Hello everyone!", recipients=["alice", "bob", "charlie"])
    result = trigger_attack("hastad")
    assert result['success'] is True
    assert result['recovered']['plaintext'] == "Hello everyone!"

def test_replay_attack_is_detected():
    """Gửi lại nonce đã dùng → server từ chối."""
    packet = alice_sends("bob", "original message")
    response = resend_packet(packet)  # Gửi lại gói tin cũ
    assert response['error']['code'] == "NONCE_ALREADY_USED"

def test_profile_persists_after_router_restart():
    """Profile đã chọn phải còn sau khi restart Router."""
    set_profile("bleichenbacher_vulnerable")
    restart_container("router")
    time.sleep(3)
    status = get_system_status()
    assert status['active_profile'] == "bleichenbacher_vulnerable"
```

### 8.3. Smoke Test — Kiểm tra Nhanh khi Khởi động

Script tự động chạy khi `docker compose up` hoàn tất, xác nhận toàn bộ hệ thống sẵn sàng:

```bash
#!/bin/bash
# scripts/smoke_test.sh

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
check "Router health"         "curl -sf http://router:5000/health"
check "GET /pubkeys"          "curl -sf http://router:5000/pubkeys"
check "GET /admin/status"     "curl -sf http://router:5000/admin/status"
check "WebSocket /ws/monitor" "wscat -c ws://router:5000/ws/monitor --execute ''"

echo "── Node Registration ──────────────────────"
check "Alice registered"   "curl -sf http://router:5000/pubkey/alice"
check "Bob registered"     "curl -sf http://router:5000/pubkey/bob"
check "Charlie registered" "curl -sf http://router:5000/pubkey/charlie"

echo "── Attack Modules ─────────────────────────"
check "Wiener module"         "docker exec eve python3 -c 'from attacks import wiener; print(\"ok\")'"
check "Hastad module"         "docker exec eve python3 -c 'from attacks import hastad; print(\"ok\")'"
check "Common modulus module" "docker exec eve python3 -c 'from attacks import common_modulus; print(\"ok\")'"
check "Bleichenbacher module" "docker exec eve python3 -c 'from attacks import bleichenbacher; print(\"ok\")'"
check "Factor module"         "docker exec eve python3 -c 'from attacks import factor_n; print(\"ok\")'"

echo "── Dashboard ──────────────────────────────"
check "User dashboard (Alice)" "curl -sf http://alice:3000"
check "Attacker dashboard"     "curl -sf http://eve:3000"
check "Jupyter Lab"            "curl -sf http://eve:8888/api/status"

echo "═══════════════════════════════════════════"
echo "  PASSED: $PASS  |  FAILED: $FAIL"
echo "═══════════════════════════════════════════"
[ $FAIL -eq 0 ] && exit 0 || exit 1
```

### 8.4. Bảng Tổng Hợp Coverage Kiểm thử

| Attack Module | Unit Test | Integration Test | Smoke Test | Ghi chú |
|---|---|---|---|---|
| Brute Force | ✅ | ✅ | ✅ | Chỉ test với key cực nhỏ (32-bit) |
| Factor n | ✅ | ✅ | ✅ | Fermat + Pollard's Rho |
| MITM Attack | ✅ | ✅ | ✅ | Test pubkey override |
| CCA Oracle | ✅ | ✅ | ✅ | Test tính nhân tính RSA |
| Bleichenbacher | ✅ | ✅ | ✅ | Test padding oracle response |
| Wiener | ✅ | ✅ | ✅ | Test recovered d |
| Håstad | ✅ | ✅ | ✅ | Test với 3 recipients |
| Common Modulus | ✅ | ✅ | ✅ | Test gcd(e1,e2)=1 |
| Replay Attack | ❌ | ✅ | ✅ | Không cần unit test riêng |
| Message Protocol | ✅ | ✅ | ✅ | Validate JSON schema |
| Persistence | ❌ | ✅ | ✅ | Test qua integration |
| Profile System | ✅ | ✅ | ✅ | Test từng profile |
