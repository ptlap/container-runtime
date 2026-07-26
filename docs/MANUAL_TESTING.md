# 🧪 Kịch Bản Kiểm Thử Thủ Công Toàn Diện (Comprehensive Manual Testing Scenarios)

Tài liệu này cung cấp các kịch bản kiểm thử chi tiết bao quát toàn bộ các tính năng hiện có của runtime `crun` nhằm kiểm chứng các cơ chế cô lập của nhân Linux (Namespaces, Cgroups v2, Seccomp, Chặn Privilege Escalation), Mạng ảo, Quản lý ảnh cục bộ, và các tính năng chẩn đoán đặc biệt khác.

---

## 🏗️ 1. Môi Trường Chuẩn Bị

Đảm bảo bạn đã biên dịch mã nguồn bản tối ưu:
```bash
cargo build --release
```

Toàn bộ các lệnh dưới đây đều thực hiện từ thư mục gốc của dự án: `file:///home/lap/container-runtime`.

---

## 🏁 2. Các Kịch Bản Kiểm Thử (12 Scenarios)

### Kịch Bản 1: Chạy Container Tương Tác (Interactive Mode - Bridge Network)
*Kiểm chứng: Cô lập TTY, Mạng bridge cấp IP động, và Cơ chế Cgroup bộ nhớ.*

1. **Khởi chạy container**:
   ```bash
   sudo target/release/crun run -t --net bridge --security default test-interactive examples/bundle
   ```
2. **Kiểm tra card mạng (bên trong container)**:
   ```sh
   ip a
   ```
   *Yêu cầu*: Thấy giao tiếp `eth0` có IP động thuộc dải `10.88.{octet}.2` và trạng thái `UP`.
3. **Kiểm tra kết nối Internet (bên trong container)**:
   ```sh
   ping -c 3 8.8.8.8
   ```
   *Yêu cầu*: Gửi/nhận gói tin thành công qua iptables NAT trên máy host.
4. **Kiểm tra giới hạn RAM (bên trong container)**:
   ```sh
   cat /sys/fs/cgroup/memory.max
   ```
   *Yêu cầu*: Trả về `268435456` bytes (256MB).
5. **Thoát container**:
   ```sh
   exit
   ```

---

### Kịch Bản 2: Kiểm Thử các Chế Độ Mạng (Network Modes)
*Kiểm chứng: Khả năng cô lập mạng ở 3 chế độ `none`, `host`, và `bridge`.*

*   **Chế độ None (Cách ly mạng hoàn toàn)**:
    1. Khởi chạy:
       ```bash
       sudo target/release/crun run -t --net none --security default test-net-none examples/bundle
       ```
    2. Kiểm tra mạng bên trong container:
       ```sh
       ip a
       ```
       *Yêu cầu*: Chỉ thấy giao tiếp loopback `lo`. Không có `eth0`. Gõ `exit` để thoát.
    3. Dọn dẹp:
       ```bash
       sudo target/release/crun delete test-net-none
       ```

*   **Chế độ Host (Dùng chung mạng máy chủ)**:
    1. Khởi chạy:
       ```bash
       sudo target/release/crun run -t --net host --security default test-net-host examples/bundle
       ```
    2. Kiểm tra mạng bên trong container:
       ```sh
       ip a
       ```
       *Yêu cầu*: Thấy toàn bộ card mạng thật của máy host (như `eth0`, `wlan0`, `lo`...). Gõ `exit` để thoát.
    3. Dọn dẹp:
       ```bash
       sudo target/release/crun delete test-net-host
       ```

---

### Kịch Bản 3: Kiểm Thử Cấu Hình Bảo Mật (Security Profiles)
*Kiểm chứng: Sự khác biệt giữa cấu hình bảo mật `default` (chặn qua seccomp) và `unconfined` (cho phép syscall).*

*   **Chế độ Default (Có seccomp chặn syscall)**:
    1. Khởi chạy:
       ```bash
       sudo target/release/crun run -t --net none --security default test-sec-def examples/bundle
       ```
    2. Thử thực hiện lệnh `mount` bên trong container:
       ```sh
       mount -t tmpfs tmpfs /mnt
       ```
       *Yêu cầu*: Lệnh thất bại với lỗi `Permission denied` hoặc `Operation not permitted`. Gõ `exit` để thoát.
    3. Dọn dẹp:
       ```bash
       sudo target/release/crun delete test-sec-def
       ```

*   **Chế độ Unconfined (Tắt Seccomp bảo mật)**:
    1. Khởi chạy:
       ```bash
       sudo target/release/crun run -t --net none --security unconfined test-sec-uncon examples/bundle
       ```
    2. Thử thực hiện lệnh `mount` bên trong container:
       ```sh
       mount -t tmpfs tmpfs /mnt
       df -h | grep /mnt
       ```
       *Yêu cầu*: Lệnh thực hiện thành công và phân vùng tmpfs mới được mount vào `/mnt`. Gõ `exit` để thoát.
    3. Dọn dẹp:
       ```bash
       sudo target/release/crun delete test-sec-uncon
       ```

---

### Kịch Bản 4: Giới Hạn Số Lượng Tiến Trình (PIDs Limit Exhaustion)
*Kiểm chứng: Cơ chế Cgroup v2 PIDs ngăn chặn fork-bomb.*

1. **Khởi chạy container**:
   ```bash
   sudo target/release/crun run -t --net none --security default test-pid-limit examples/bundle
   ```
2. **Kiểm tra giới hạn tối đa số PIDs (bên trong container)**:
   ```sh
   cat /sys/fs/cgroup/pids.max
   ```
   *Yêu cầu*: In ra giá trị giới hạn số PIDs (ví dụ: `64` hoặc số cấu hình tương ứng trong cgroups).
3. **Thử nghiệm vượt giới hạn**:
   Chạy lệnh fork nhiều tiến trình ngầm:
   ```sh
   for i in $(seq 1 80); do sleep 10 & done
   ```
   *Yêu cầu*: Hệ thống sẽ báo lỗi `sh: can't fork` hoặc `Resource temporarily unavailable` sau khi chạm mốc giới hạn, chứng minh Cgroups v2 PIDs limit hoạt động chính xác. Gõ `exit` để thoát (hoặc tắt container).
4. **Dọn dẹp**:
   ```bash
   sudo target/release/crun delete test-pid-limit
   ```

---

### Kịch Bản 5: Vòng Đời Container Chạy Ngầm (Detached Lifecycle)
*Kiểm chứng: Khả năng điều phối và kiểm soát trạng thái container qua API CLI.*

1. **Tạo container ở trạng thái chờ (`created`)**:
   ```bash
   sudo target/release/crun create --net none --security default test-detached examples/bundle
   ```
2. **Kiểm tra trạng thái**:
   ```bash
   sudo target/release/crun state test-detached --json
   ```
   *Yêu cầu*: Trạng thái hiển thị `"status": "created"`.
3. **Khởi động container**:
   ```bash
   sudo target/release/crun start test-detached
   ```
4. **Kiểm tra trạng thái đang chạy**:
   ```bash
   sudo target/release/crun state test-detached --json
   ```
   *Yêu cầu*: Trạng thái hiển thị `"status": "running"`.
5. **Thực thi lệnh vào container đang chạy (Exec)**:
   ```bash
   sudo target/release/crun exec test-detached ps aux
   ```
   *Yêu cầu*: Hiển thị danh sách tiến trình đang chạy trong container.
6. **Dừng container**:
   ```bash
   sudo target/release/crun stop test-detached --timeout 2
   ```
7. **Xóa container**:
   ```bash
   sudo target/release/crun delete test-detached
   ```

---

### Kịch Bản 6: Đánh Giá Cấu Hình An Ninh (Inspect Security Posture)
*Kiểm chứng: Lệnh chẩn đoán tư thế bảo mật hoạt động đúng.*

1. **Tạo container**:
   ```bash
   sudo target/release/crun create --net none --security default test-inspect examples/bundle
   ```
2. **Kiểm tra cấu hình an ninh**:
   ```bash
   sudo target/release/crun inspect-security test-inspect
   ```
   *Yêu cầu*: Báo cáo hiển thị rõ ràng thông số: `NoNewPrivs: true`, `Seccomp: default`, các `Capabilities` bị drop, các thông số Cgroup Limits.
3. **Dọn dẹp**:
   ```bash
   sudo target/release/crun delete test-inspect
   ```

---

### Kịch Bản 7: So Sánh Thay Đổi Tập Tin (OverlayFS Rootfs Diff)
*Kiểm chứng: Trích xuất các thay đổi trên Layer ghi (upperdir) của OverlayFS.*

1. **Tạo và khởi chạy container ngầm**:
   ```bash
   sudo target/release/crun create --net none --security default test-diff examples/bundle
   sudo target/release/crun start test-diff
   ```
2. **Tạo, sửa đổi và xóa tập tin bên trong container**:
   ```bash
   sudo target/release/crun exec test-diff touch /new_file.txt
   sudo target/release/crun exec test-diff sh -c "echo 'changed' > /etc/hostname"
   sudo target/release/crun exec test-diff rm /etc/hosts
   ```
3. **Xem các thay đổi (Diff)**:
   ```bash
   sudo target/release/crun diff test-diff
   ```
   *Yêu cầu*: Đầu ra hiển thị rõ ràng:
   *   `A /new_file.txt` (Added)
   *   `C /etc/hostname` (Changed)
   *   `D /etc/hosts` (Deleted)
4. **Dọn dẹp**:
   ```bash
   sudo target/release/crun stop test-diff
   ```

---

### Kịch Bản 8: Theo Dõi Syscall và Tiến Trình (Trace Mode)
*Kiểm chứng: Khả năng truy vết tiến trình thực tế bằng `/proc` và công cụ `strace`.*

1. **Khởi chạy container ngầm chạy một vòng lặp**:
   ```bash
   sudo target/release/crun create --net none --security default test-trace examples/bundle
   sudo target/release/crun start test-trace
   ```
2. **Theo dõi thông tin tiến trình**:
   ```bash
   sudo target/release/crun trace test-trace
   ```
   *Yêu cầu*: Hiển thị sơ đồ cây tiến trình PID và tài nguyên tiêu thụ từ `/proc`.
3. **Theo dõi bằng strace (nếu máy có cài `strace`)**:
   ```bash
   sudo target/release/crun trace test-trace --strace --duration-ms 2000
   ```
   *Yêu cầu*: Bắt được các cuộc gọi hệ thống (syscall) mà tiến trình container đang thực hiện trong vòng 2 giây.
4. **Dọn dẹp**:
   ```bash
   sudo target/release/crun stop test-trace
   sudo target/release/crun delete test-trace
   ```

---

### Kịch Bản 9: Quản Lý và Khởi Chạy Ảnh (Local Image Storage)
*Kiểm chứng: Tính năng lưu trữ cục bộ, import và khởi chạy độc lập.*

1. **Nén thư mục rootfs thành tarball**:
   ```bash
   tar -C examples/bundle/rootfs -cf /tmp/my-image.tar .
   ```
2. **Import ảnh vào `crun`**:
   ```bash
   sudo target/release/crun image import /tmp/my-image.tar local-alpine
   ```
3. **Xem danh sách ảnh**:
   ```bash
   sudo target/release/crun image list
   ```
   *Yêu cầu*: Hiển thị ảnh `local-alpine` trong bảng danh sách.
4. **Khởi chạy trực tiếp từ ảnh cục bộ**:
   ```bash
   sudo target/release/crun run-image -t local-alpine test-img-run
   ```
   *Yêu cầu*: Bạn chui được vào shell của container. Gõ `exit` để thoát.
5. **Dọn dẹp**:
   ```bash
   sudo target/release/crun delete test-img-run
   rm -f /tmp/my-image.tar
   ```

---

### Kịch Bản 10: Tự Động Phục Hồi Tài Nguyên Rác (Doctor Mode)
*Kiểm chứng: Khả năng phát hiện và tự động giải phóng tài nguyên rác của `crun`.*

1. **Tạo tài nguyên rác giả lập**:
   Tạo thư mục trạng thái giả của một container không tồn tại tiến trình thực tế:
   ```bash
   sudo mkdir -p /run/crun-rs/stale-container
   sudo sh -c 'echo "{\"id\":\"stale-container\",\"pid\":999999,\"status\":\"running\"}" > /run/crun-rs/stale-container/state.json'
   ```
2. **Chạy chẩn đoán lỗi**:
   ```bash
   sudo target/release/crun doctor
   ```
   *Yêu cầu*: Phát hiện ra container `stale-container` bị mồ côi (tình trạng chết lâm sàng - Orphan/Stale).
3. **Thực thi phục hồi sửa lỗi tự động**:
   ```bash
   sudo target/release/crun doctor --fix
   ```
   *Yêu cầu*: `crun` tự động dọn dẹp thư mục `/run/crun-rs/stale-container` và các tài nguyên liên quan.
4. **Xác nhận lại**:
   ```bash
   sudo target/release/crun doctor
   ```
   *Yêu cầu*: Báo cáo hệ thống hoàn toàn sạch sẽ (`No stale resources detected`).

---

### Kịch Bản 11: Giám Sát Sức Khỏe Vòng Lặp (Health Watch Mode)
*Kiểm chứng: Engine giám sát sức khỏe thực hiện kiểm tra định kỳ.*

1. **Khởi chạy container**:
   ```bash
   sudo target/release/crun create --net none --security default test-health examples/bundle
   sudo target/release/crun start test-health
   ```
2. **Theo dõi sức khỏe thời gian thực (Watch)**:
   ```bash
   sudo target/release/crun health test-health --watch --interval-ms 1000
   ```
   *Yêu cầu*: Lệnh chạy lặp lại liên tục, in trạng thái sức khỏe container (`healthy` / `unhealthy` dựa trên cấu hình healthcheck trong `config.json`). Nhấn `Ctrl + C` để thoát theo dõi.
3. **Dọn dẹp**:
   ```bash
   sudo target/release/crun stop test-health
   sudo target/release/crun delete test-health
   ```

---

### Kịch Bản 12: Kiểm Tra Hợp Lệ Cấu Hình OCI (OCI Validation)
*Kiểm chứng: Parser kiểm định tính tương thích của file `config.json`.*

1. **Chạy kiểm định gói bundle chuẩn**:
   ```bash
   target/release/crun validate examples/bundle
   ```
   *Yêu cầu*: In ra kết quả hợp lệ cùng các cảnh báo warnings cho các trường không được hỗ trợ (nếu có).
2. **Tạo và kiểm định file cấu hình lỗi**:
   Tạo thư mục bundle lỗi tạm thời:
   ```bash
   mkdir -p /tmp/bad-bundle
   echo '{"ociVersion": "1.0.0"}' > /tmp/bad-bundle/config.json
   target/release/crun validate /tmp/bad-bundle
   ```
   *Yêu cầu*: Lệnh kết thúc với thông báo lỗi rõ ràng về việc thiếu các trường bắt buộc như `process` hoặc `root`.
3. **Dọn dẹp**:
   ```bash
   rm -rf /tmp/bad-bundle
   ```

---

### Kịch Bản 13: Học Tập Syscall (Seccomp Learn Mode)
*Kiểm chứng: Runtime quan sát và ghi lại đúng tập syscall mà workload thực sự dùng.*

1. **Chạy container ở chế độ học**:
   ```bash
   sudo target/release/crun run --net none --log on \
     --seccomp learn --seccomp-out /tmp/learn.json \
     learn-demo examples/bundle
   ```
   *Yêu cầu*: Container chạy và thoát bình thường. Không có syscall nào bị chặn.
2. **Kiểm tra capture**:
   ```bash
   jq '{events: .totalEvents, unique: (.syscalls|length), processes: .processesSeen}' /tmp/learn.json
   jq '.syscalls.execve' /tmp/learn.json
   ```
   *Yêu cầu*: `events` > 0, `unique` vài chục syscall, và `execve` xuất hiện ít nhất 1 lần (chính là lệnh exec của container).
3. **Kiểm tra log vẫn thu được** (đây là chỗ dễ hỏng nhất: tracer sở hữu `waitpid(-1)` nên nuốt cả exit status của log helper):
   ```bash
   sudo target/release/crun logs learn-demo
   ```
   *Yêu cầu*: In ra output của container, không treo.
4. **Dọn dẹp**:
   ```bash
   sudo target/release/crun delete learn-demo
   ```

---

### Kịch Bản 14: Sinh Và Thực Thi Profile (Generate & Enforce)
*Kiểm chứng: Profile sinh ra đúng schema OCI và đủ để chạy lại chính workload đó.*

1. **Sinh profile từ capture**:
   ```bash
   sudo target/release/crun seccomp generate --capture /tmp/learn.json \
     -o /tmp/learn.seccomp.json --name demo
   ```
   *Yêu cầu*: In ra `allowed_count`, `observed_syscalls`, `baseline_syscalls`. Tổng phải bằng `observed + baseline`.
2. **Kiểm tra định dạng OCI**:
   ```bash
   jq '{defaultAction, architectures, names: (.syscalls[0].names|length)}' /tmp/learn.seccomp.json
   ```
   *Yêu cầu*: `defaultAction` là `SCMP_ACT_ERRNO`, `architectures` chứa `SCMP_ARCH_X86_64`. File này phải dùng được nguyên vẹn với runc.
3. **Chạy lại dưới profile vừa sinh**:
   ```bash
   sudo target/release/crun run --net none --log on \
     --seccomp enforce --seccomp-profile /tmp/learn.seccomp.json \
     enforce-demo examples/bundle
   sudo target/release/crun logs enforce-demo
   ```
   *Yêu cầu*: Container chạy đúng như lần học, output giống hệt.
4. **Xác nhận syscall ngoài profile bị chặn**:
   ```bash
   sudo target/release/crun inspect-security enforce-demo
   ```
   *Yêu cầu*: Báo `seccomp_runtime_mode: enforce` và `seccomp_allowed_syscalls` bằng số syscall trong profile.
5. **Dọn dẹp**:
   ```bash
   sudo target/release/crun delete enforce-demo
   ```

---

### Kịch Bản 15: Đo Mức Giảm Bề Mặt Tấn Công (Compare)
*Kiểm chứng: Các con số dùng cho chương đánh giá được tính đúng.*

1. **So với profile mặc định của Docker**:
   ```bash
   target/release/crun seccomp compare /tmp/learn.seccomp.json \
     --baseline third_party/moby-profiles/seccomp/default.json \
     --cve-map data/cve-syscall-map.json
   ```
   *Yêu cầu*: `baseline_allowed` phải là **296** trên x86_64 — không phải 441. Con số 441 là đếm cả rule bị gate theo capability mà container mặc định không có; dùng nó sẽ thổi phồng mọi tỉ lệ giảm.
2. **Kiểm tra `over_allowed`**:
   *Yêu cầu*: Bằng 0 với workload thông thường. Khác 0 nghĩa là workload dùng syscall mà Docker chặn — đó là một phát hiện cần giải thích trong báo cáo, không phải lỗi.
3. **Kiểm tra dữ liệu CVE**:
   ```bash
   scripts/check-cve-map.py
   ```
   *Yêu cầu*: 0 error. Các warning `confidence is medium` là nhắc nhở phải đối chiếu NVD trước khi đưa số vào báo cáo.
4. **Chế độ dry-run** (đo false-denial mà không làm gãy workload):
   ```bash
   sudo target/release/crun doctor | grep -i seccomp || echo "kernel hỗ trợ SECCOMP_RET_LOG"
   sudo target/release/crun run --net none --log on \
     --seccomp enforce --seccomp-profile /tmp/learn.seccomp.json \
     --seccomp-action log dryrun-demo examples/bundle
   sudo target/release/crun delete dryrun-demo
   ```
   *Yêu cầu*: Container chạy bình thường; syscall lẽ ra bị chặn được ghi vào audit log thay vì bị từ chối.
