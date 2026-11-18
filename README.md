# 🕵️‍♂️ NoirDetective — Trung Tâm Điều Tra Hiện Trường, Pháp Y Số & Thẩm Vấn Phá Án Tương Tác (Port 4130)

**NoirDetective** là hệ thống mô phỏng điều tra phá án tương tác kết hợp **Pháp y Kỹ thuật số (Digital Forensics)**, **Máy đo nói dối thời gian thực (Polygraph Biometrics)** và **Đối chiếu Bẻ gãy Bằng chứng Ngoại phạm (Alibi Breaker)** trong hệ sinh thái `d:\AI_App`.

## 🌟 Tính Năng Trọng Tâm

1. **Khám Nghiệm Hiện Trường & Phòng Lab Pháp Y Số (`/api/evidence/inspect`)**:
   - Phân tích xung điện từ RFID/Proxmark3, khôi phục RAM dump MQTT Broker, định vị cường độ sóng Bluetooth Low Energy (BLE) của ví lạnh và giám định hóa sinh.
2. **Buồng Thẩm Vấn & Máy Đo Nói Dối Polygraph Thời Gian Thực (`/api/interrogate`)**:
   - Biểu đồ sóng sinh trắc học trực tiếp trên HTML5 Canvas: Nhịp tim (**BPM**), Điện trở da (**GSR μS**) và Xác suất nói dối (**Deception Probability %**).
   - **⚡ Alibi Breaker (Bẻ Gãy Ngoại Phạm)**: Đập trực tiếp vật chứng Pháp y Số mâu thuẫn với lời khai để buộc hung thủ lộ diện.
3. **Bộ Sinh Vụ Án Ngẫu Nhiên Có Logic Chặt Chẽ (`/api/case/generate`)**:
   - Tự động khởi tạo các kịch bản vụ án mới với chuỗi thời gian, dấu vết mạng (C2 IP, Burner Phone, Domain) và bằng chứng đối chất 100% có lời giải.
4. **Cầu Nối Liên Thông OmniTrace OSINT (`/api/osint/push`)**:
   - Đẩy tự động toàn bộ dấu vết số thu giữ tại hiện trường sang đồ thị điều tra **OmniTrace OSINT (`Port 4090`)**.

## 🚀 Khởi Chạy & Kiểm Thử

```bash
# Khởi chạy máy chủ trên cổng 4130
node server.js

# Chạy bộ kiểm thử tự động
node test_server.js
```

