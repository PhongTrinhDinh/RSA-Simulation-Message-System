# 🔐 Sandbox Kiểm thử Tấn công Hệ thống Tin nhắn OTT

Dự án này là một môi trường giả lập (sandbox) dựa trên Docker, được thiết kế để mô phỏng và nghiên cứu các kỹ thuật tấn công mã hóa RSA và giao thức mạng trên một hệ thống tin nhắn OTT (Over-The-Top).

## 📝 Mô tả dự án

### Mục đích của dự án
Dự án được xây dựng nhằm cung cấp một môi trường thực hành trực quan cho sinh viên và các nhà nghiên cứu an toàn thông tin. Mục tiêu chính là minh họa cách các lỗ hổng trong cấu hình mã hóa và thiết kế giao thức có thể bị khai thác trong thực tế, từ đó nhấn mạnh tầm quan trọng của việc triển khai các tiêu chuẩn bảo mật hiện đại.

### Công nghệ sử dụng và lý do lựa chọn
- **Python (FastAPI, PyCryptodome, gmpy2, sympy)**: Python là ngôn ngữ chủ đạo nhờ hệ sinh thái thư viện toán học và mật mã phong phú. FastAPI được sử dụng để xây dựng các REST API và WebSocket nhanh chóng, hiệu quả.
- **Docker & Docker Compose**: Cho phép giả lập một hệ thống mạng phức tạp với nhiều thành phần (Router, Alice, Bob, Eve) một cách cô lập và dễ dàng triển khai trên bất kỳ máy tính nào mà không cần cài đặt nhiều phụ thuộc.
- **HTML/JS thuần & HTMX**: Sử dụng cho giao diện người dùng (Dashboard). Lựa chọn này giúp giảm bớt sự phức tạp của các build pipeline hiện đại (như npm, webpack), phù hợp cho mục đích giáo dục nhưng vẫn đảm bảo giao diện trực quan và tương tác thời gian thực.

### Thách thức so với hệ thống thực tế
Hệ thống này là một phiên bản đơn giản hóa của các hệ thống OTT thực tế, dẫn đến một số khác biệt:
- **Cơ chế Mirror Traffic**: Trong môi trường thật, kẻ tấn công thường phải thực hiện các kỹ thuật như ARP Spoofing hoặc chiếm quyền kiểm soát nút mạng để bắt gói tin. Ở đây, Router chủ động "mirror" gói tin sang Eve để đơn giản hóa quá trình học tập.
- **Xác thực Public Key**: Các hệ thống thực tế (như Signal, WhatsApp) sử dụng cơ chế xác thực danh tính và chứng chỉ phức tạp. Sandbox này cố ý bỏ qua xác thực để cho phép thực hiện các cuộc tấn công như Man-in-the-Middle (MITM).
- **Mô phỏng mạng**: Toàn bộ các node chạy trên cùng một Docker Network, loại bỏ các vấn đề về độ trễ, mất gói tin hoặc tường lửa phức tạp trong môi trường Internet thực.

---

## 📖 Mục lục
1. [Yêu cầu hệ thống](#-yêu-cầu-hệ-thống)
2. [Cài đặt](#-cài-đặt)
3. [Cách chạy](#-cách-chạy)
4. [Hướng dẫn sử dụng](#-hướng-dẫn-sử-dụng)
5. [Khuyến cáo giáo dục](#-khuyến-cáo-giáo-dục)
6. [Đóng góp](#-đóng-góp)

---

## 💻 Yêu cầu hệ thống
- Máy tính đã cài đặt **Docker** và **Docker Compose**.
- RAM tối thiểu 4GB để chạy ổn định các container.

## 🛠 Cài đặt
1. Sao chép mã nguồn về máy cục bộ:
   ```bash
   git clone <repository_url>
   cd simulations_4
   ```
2. Đảm bảo Docker đã được khởi động.

## 🚀 Cách chạy
Khởi chạy toàn bộ hệ thống bằng Docker Compose:
```bash
docker compose up --build
```
Sau khi các container khởi động thành công, bạn có thể truy cập các Dashboard qua trình duyệt.

## 🎮 Hướng dẫn sử dụng

### Truy cập các thành phần
| Thành phần | URL | Chức năng |
|---|---|---|
| **Eve (Attacker)** | `http://localhost:3000` | Dashboard quản lý tấn công và giám sát traffic. |
| **Alice** | `http://localhost:3001` | Giao diện Chat của người dùng Alice. |
| **Bob** | `http://localhost:3002` | Giao diện Chat của người dùng Bob. |
| **Charlie** | `http://localhost:3003` | Giao diện Chat của người dùng Charlie. |
| **Router API** | `http://localhost:5000` | API trung tâm và quản lý hệ thống. |

### Các bước thực hiện một cuộc tấn công
1. **Chọn kịch bản**: Trên Dashboard của Eve, chọn một **Attack Profile** phù hợp (ví dụ: `wiener_vulnerable`).
2. **Gửi tin nhắn**: Mở Dashboard của Alice hoặc Bob, gửi một vài tin nhắn qua lại. Bạn sẽ thấy bản mã (ciphertext) xuất hiện trên monitor của Eve.
3. **Thực thi tấn công**: Quay lại Dashboard của Eve, tìm đến mục **Attack Arsenal**, chọn loại tấn công tương ứng với profile đã chọn và nhấn **Run**.
4. **Xem kết quả**: Kết quả (khóa bí mật bị lộ, bản rõ tin nhắn...) sẽ hiển thị trực tiếp trên giao diện của Eve.

---

## ⚠️ Khuyến cáo giáo dục
Dự án này được tạo ra **duy nhất cho mục đích giáo dục và nghiên cứu an toàn thông tin**. Việc sử dụng các kiến thức và công cụ trong dự án này để tấn công các hệ thống thực tế mà không có sự cho phép là bất hợp pháp và vi phạm đạo đức nghề nghiệp. Chúng tôi không chịu trách nhiệm về bất kỳ thiệt hại nào gây ra bởi việc sử dụng sai mục đích dự án này.

## 🤝 Đóng góp
Dự án được phát triển và hoàn thiện bởi:
- **Nguyễn Nam Trung**
- **Lê Tiến Đạt**

Chúng tôi hoan nghênh mọi ý kiến đóng góp và báo lỗi để giúp dự án hoàn thiện hơn.
