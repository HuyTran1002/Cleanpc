# 🚀 CleanPC Master - Hệ Thống Dọn Dẹp, Tối Ưu Ổ Cứng & Quản Lý RAM Siêu Tốc (Zero-Lag)

**CleanPC Master** là giải pháp phần mềm tối ưu hóa máy tính Windows toàn diện, kết hợp sức mạnh của:
1. **Dọn rác ổ cứng chuyên sâu & Tìm tệp trùng lặp SHA-256**.
2. **Theo dõi sức khỏe S.M.A.R.T & Đo nhiệt độ ổ cứng thời gian thực** (Hỗ trợ NVMe SSD & SATA).
3. **Cơ chế quản lý & Tự động dọn RAM chuẩn Mem Reduct** (Giải phóng Standby List, Working Sets qua Windows NT Native API).
4. **Hệ thống Gaming Guard & Anti-Lag độc quyền**: Cam kết **0% Drop FPS, 0% Giật Lag** khi chạy ngầm hoặc chơi game.
5. **Phiên bản 1 File Thực Thi `.EXE` Độc Lập** (`CleanPC_Master.exe` ~16 MB) - Chạy ngay không cần cài đặt Python.

---

## 🌟 4 Trụ Cột Tính Năng Đột Phá

### 1. 🧠 Quản Lý RAM Thời Gian Thực & Auto-Clean (Chuẩn Mem Reduct)
- **Cơ chế làm việc của Windows Memory Management**:
  - Khi ứng dụng tắt đi, Windows không xóa dữ liệu ngay mà giữ lại trong **Standby List** (Bộ nhớ chờ / Bộ đệm tập tin). Khi RAM chạm ngưỡng 85-90%, Windows mới bắt đầu hoán vị (paging) gây hiện tượng khựng máy (micro-stutter).
- **Công nghệ giải phóng bộ nhớ Native NT API**:
  - Sử dụng hàm cấp kernel `NtSetSystemInformation` (SystemMemoryListInformation - Class 80) với quyền `SeProfileSingleProcessPrivilege` & `SeIncreaseQuotaPrivilege`.
  - **MemoryPurgeStandbyList (Opcode 2)**: Xóa sạch bộ nhớ Standby cache của hệ thống chỉ trong vài mili-giây.
  - **MemoryFlushModifiedList (Opcode 1)**: Ép ghi các trang bộ nhớ đã chỉnh sửa xuống đĩa để thu hồi RAM.
  - **K32EmptyWorkingSet**: Thu gọn bộ nhớ làm việc của các tiến trình chạy nền không hoạt động.
- **Tự động dọn dẹp thông minh (Auto-Clean Daemon)**:
  - Cho phép tùy chỉnh ngưỡng kích hoạt tự động (mặc định 80% RAM).
  - Tự động kiểm tra định kỳ mỗi 15 giây.

---

### 2. 🛡️ Công Nghệ Gaming Guard & Chống Drop FPS Tuyệt Đối (Anti-Lag Architecture)
Nỗi sợ lớn nhất của game thủ khi dùng các app dọn RAM là đang bắn súng, combat thì bị khựng hình (drop FPS). CleanPC Master giải quyết triệt để nhờ 4 lớp bảo vệ:
1. **Lớp 1: Loại trừ ứng dụng tiền cảnh (Foreground Window Protection)**:
   - Sử dụng `GetForegroundWindow` và `GetWindowThreadProcessId` để nhận diện game/phần mềm người dùng đang thao tác.
   - **Tuyệt đối KHÔNG gọi EmptyWorkingSet** lên tiến trình tiền cảnh để tránh làm sụt giảm tài nguyên của game.
2. **Lớp 2: Cảm biến phát hiện Game Fullscreen D3D (`SHQueryUserNotificationState`)**:
   - Tự động nhận diện khi máy tính đang chạy game Fullscreen DirectX/OpenGL (`QUNS_RUNNING_D3D_FULL_SCREEN = 3`) hoặc chế độ bận toàn màn hình (`QUNS_BUSY = 2`).
   - Khi phát hiện Game đang chạy, Daemon tự động **tạm hoãn dọn RAM chạy ngầm** cho tới khi bạn thoát game.
3. **Lớp 3: Luồng ưu tiên cực thấp (`THREAD_PRIORITY_IDLE`)**:
   - Luồng quét ngầm được gán mức ưu tiên `-15` (Idle Priority). Windows chỉ cấp CPU cho nó khi toàn bộ hệ thống rảnh rỗi 100%, không bao giờ tranh chấp CPU với Game hay tác vụ Render/Code.
4. **Lớp 4: Cơ chế Anti-Thrashing Cooldown (180 giây)**:
   - Sau mỗi lần dọn, hệ thống bắt buộc nghỉ tối thiểu 3 phút trước lần dọn kế tiếp, ngăn chặn triệt để tình trạng lặp vòng dọn/đọc đĩa liên tục gây nghẽn I/O.

---

### 3. 🌡️ Giám Sát Sức Khỏe Ổ Cứng S.M.A.R.T & Tối Ưu Hóa (TRIM SSD)
- **Đọc trực tiếp cảm biến phần cứng qua Storage API**:
  - Nhận diện model phần cứng: **NVMe SSD** (Micron 3400, ADATA LEGEND 850 LITE, Samsung, Kingston,...) & **SATA SSD/HDD**.
  - **Nhiệt độ thời gian thực (°C)**: Kèm huy hiệu cảnh báo màu sắc (Mát mẻ < 45°C, Bình thường 45-60°C, Quá nhiệt > 60°C).
  - **Mức độ hao mòn ô nhớ (Wear Level %)**: Đánh giá tuổi thọ còn lại của chip nhớ NAND Flash.
  - **Thời gian hoạt động (Power On Hours)**: Tổng số giờ ổ đĩa đã chạy từ lúc xuất xưởng.
  - **Số lỗi đọc dữ liệu (Read Errors Count)**: Phát hiện sớm ổ đĩa sắp hỏng.
- **Tối ưu hóa TRIM (`Optimize-Volume -ReTrim`)**:
  - Gửi lệnh TRIM chuyên dụng cho SSD để giải phóng các khối nhớ chết, phục hồi tốc độ đọc/ghi đỉnh cao mà không gây hại chip nhớ như chống phân mảnh (Defrag).

---

### 4. 🧹 Dọn Rác Chuyên Sâu & Tìm Tệp Trùng Lặp Siêu Tốc
- **Dọn rác hệ thống**: `%TEMP%`, `C:\Windows\Temp`, Windows Crash Dumps, Browser Caches (Chrome/Edge/Brave), Thumbnail Cache, pip/npm cache.
- **Tìm tệp trùng lặp 3 giai đoạn**:
  - Giai đoạn 1: Lọc theo kích thước byte.
  - Giai đoạn 2: Lọc sơ bộ bằng Quick Partial MD5 (4KB đầu & cuối).
  - Giai đoạn 3: Băm đầy đủ SHA-256 đa luồng.
  - Tự động đề xuất giữ lại bản gốc (cũ nhất) và tích chọn bản sao để xóa.
- **Bảo vệ an toàn dữ liệu**: Chuyển file vào **Thùng rác (Recycle Bin)** qua `SHFileOperationW`, có thể phục hồi lại 100%.

---

### 5. 🔔 Chạy Ngầm Khay Hệ Thống (System Tray) & Hiển Thị Số RAM Thời Gian Thực
- **Tự động thu nhỏ khi bấm tắt [X]**:
  - Khi bạn nhấp vào nút đóng [X] của cửa sổ hoặc nút "Thu nhỏ Tray", ứng dụng **không bị tắt** mà tự động ẩn vào khay hệ thống (System Tray).
  - Có thông báo bóng bóng (Balloon Notification) thông báo ứng dụng đang tiếp tục bảo vệ hệ thống.
- **Biểu tượng Tray động hiển thị chính xác % RAM**:
  - Tự động đo và vẽ số phần trăm RAM (ví dụ: `45`, `68`, `85`) ngay trên khay Taskbar của Windows.
  - Mã màu trực quan:
    - 🟢 **Xanh lá (< 60%)**: Trạng thái lý tưởng, bộ nhớ thông thoáng.
    - 🟡 **Cam (60% - 80%)**: Mức tải trung bình.
    - 🔴 **Đỏ (>= 80%)**: Báo động bộ nhớ đầy, cần dọn dẹp.
- **Menu chuột phải tiện lợi**:
  - **Mở CleanPC Master**: Bấm đúp hoặc chọn từ menu để mở lại giao diện bất kỳ lúc nào.
  - **⚡ Dọn RAM ngay (Mem Reduct)**: Kích hoạt thu hồi Standby List cấp tốc ngay từ khay mà không cần mở giao diện.
  - **❌ Thoát hoàn toàn**: Đóng triệt để toàn bộ ứng dụng và máy chủ.
- **Hover Tooltip chi tiết**: Rê chuột vào icon để xem tức thì: `CleanPC Master - RAM: 68% (10.8/15.8 GB)`.

---

## 📦 Bản Phát Hành 1 File .EXE (Single-File Release)

Tệp thực thi độc lập đã được biên dịch sẵn trong thư mục:
👉 **`dist/CleanPC_Master.exe`** (Dung lượng: ~24.9 MB)

### Ưu điểm vượt trội của bản Release .EXE:
- **Tích hợp sẵn Logo Khiên Điện Tử Cybernetic**: Biểu tượng ứng dụng chính thức sang trọng, hiển thị trên File Explorer và Taskbar.
- **Zero-Dependency**: Chạy độc lập trên mọi máy tính Windows 10 / Windows 11 (64-bit) mà không cần cài đặt Python.
- **Auto UAC Elevation**: Tự động kích hoạt quyền Quản trị viên (Administrator) để truy cập đầy đủ cảm biến S.M.A.R.T và NT Memory API.
- **Giao diện Cửa sổ Desktop Native**: Tích hợp WebView2 mượt mà, khung kính mờ Dark Glassmorphism sang trọng.
- **Portable**: Bạn có thể copy tệp này sang USB hoặc bất kỳ thư mục nào trên máy để sử dụng ngay lập tức.

---

## 🛠️ Hướng Dẫn Tự Đóng Gói (Build from Source)

Nếu bạn muốn tùy biến mã nguồn và tự đóng gói lại tệp `.EXE`:

1. Cài đặt các thư viện phụ thuộc:
```bash
pip install pyinstaller pywebview
```

2. Chạy kịch bản tự động đóng gói:
```bash
python build_exe.py
```

File `.EXE` thành phẩm sẽ xuất hiện trong thư mục `dist/CleanPC_Master.exe`.

---

## 💻 Hướng Dẫn Chạy Dành Cho Nhà Phát Triển (Dev Mode)

Nếu muốn chạy dưới dạng mã nguồn mở để debug:
```bash
# Chế độ Desktop App WebView2:
python desktop.py

# Hoặc chế độ Web Server:
python app.py
```
Truy cập giao diện Web tại: `http://localhost:8899`
