# iOSAutomate v1.5.3 — License Bypass PoC: Patch Notes

Target package: `com.fn.rh.iOSAutomate-1.5.3-3-roothide-iphoneos-arm64e.deb`  
Binary: `0a04abcf5ee4aiam7b7c131c.dylib` — FAT Mach-O, 5,565,856 bytes  
Slices: arm64 @ FAT+0x4000 | arm64e @ FAT+0x2A8000

---

## Tổng quan kiến trúc license check

Khi tweak load, cơ chế kiểm tra license gồm 3 lớp:

```
1. Startup check (InitFunc_0 constructor)
      └─► offline_PBKDF2()    — kiểm tra PBKDF2 hash của license key
      └─► lc_verify()         — xác minh trạng thái license tổng thể
      └─► expiry_gate()       — kiểm tra ngày hết hạn

2. Runtime periodic check (timer ~43–63 giây sau khi chạy)
      └─► sub_82928 scheduler → sub_825DC() — inline PBKDF2 check
              nếu fail → hiển thị toast "[F]" + kill script sau 5s

3. Script execution hooks (Lua VM + các trigger khác)
      └─► sub_102A5C() — master license consistency gate
              gọi từ: sub_825DC, sub_834D8, sub_84148, sub_16464, sub_E9028, sub_19460
              sub_19460 được hook vào _luaD_call + _luaV_execute → fire mỗi ~256 Lua instructions
```

Cả 3 lớp phải được bypass để tweak hoạt động hoàn toàn.

---

## Lưu ý kỹ thuật quan trọng trước khi đọc patch table

### ARM64 vs ARM64E — PACIBSP + RETAB

Mọi function trong slice arm64e đều bắt đầu bằng `PACIBSP` (`7F 23 03 D5`).  
PACIBSP ký X30 (LR) bằng B key + SP làm salt → cuối function `RETAB` authenticate + strip PAC → branch về caller.

**Cách patch đúng (v1.5.3-6+):**

Giữ PACIBSP nguyên tại +0. Patch 8 bytes tại **+4** (instruction sau PACIBSP):
```
+0: 7F 23 03 D5  PACIBSP     ← giữ nguyên, LR được ký bình thường
+4: XX XX 80 52  MOV W0,#X   ← patch tại đây
+8: FF 0B 5F D6  RETAB       ← patch tại đây, authenticate+return
```

**Tại sao không overwrite PACIBSP (cách cũ)?**

- Nếu caller dùng `BLRAB` (authenticated call — phổ biến trong arm64e ABI), X30 đã chứa PAC-signed address trước khi enter function.
- Nếu ta skip PACIBSP và dùng plain `RET`: branch tới địa chỉ có PAC bits → instruction fetch fault trên iOS 16+ với strict PAC enforcement.
- Nếu ta skip PACIBSP và dùng `RETAB`: RETAB cố authenticate X30 chưa được ký bởi B+SP → PAC mismatch → fault.
- **Kết luận**: Cách duy nhất an toàn là giữ PACIBSP (để LR được ký), rồi dùng RETAB để pair đúng.

> **Tại sao arm64 dùng plain RET?** Slice arm64 không có PACIBSP, không có PAC signing — `RET` là đủ.

Slice arm64 không có PACIBSP → patch thẳng từ đầu function.

### Patch bytes dùng trong PoC

**arm64 (patch tại function start, plain RET):**

| Mã | Bytes (LE) | Ý nghĩa |
|---|---|---|
| `MOV W0,#0; RET` | `00 00 80 52  C0 03 5F D6` | Return false/0 |
| `MOV W0,#1; RET` | `20 00 80 52  C0 03 5F D6` | Return true/1 |
| `MOV W0,#17; RET` | `20 02 80 52  C0 03 5F D6` | Return 17 (PBKDF2 magic) |
| `NOP; RET` | `1F 20 03 D5  C0 03 5F D6` | Trả về ngay, không làm gì |

**arm64e (patch tại +4 sau PACIBSP, dùng RETAB):**

| Mã | Bytes (LE) | Ý nghĩa |
|---|---|---|
| `MOV W0,#0; RETAB` | `00 00 80 52  FF 0B 5F D6` | Return false/0 |
| `MOV W0,#1; RETAB` | `20 00 80 52  FF 0B 5F D6` | Return true/1 |
| `MOV W0,#17; RETAB` | `20 02 80 52  FF 0B 5F D6` | Return 17 (PBKDF2 magic) |
| `NOP; RETAB` | `1F 20 03 D5  FF 0B 5F D6` | Trả về ngay, không làm gì |

Mỗi patch đều đúng 8 bytes — overwrite 2 instruction liên tiếp.

---

## 11 License Bypass Patches

### 1. `offline_PBKDF2` — arm64 | FAT+0x1069DC

**Symbol**: `_ws_3c03af885e89f55e`  
**Patch**: `20 02 80 52 C0 03 5F D6` → `MOV W0,#17; RET`

**Cách tìm**: Export symbol table của dylib liệt kê tên bị obfuscate. Symbol này map đến function thực hiện PBKDF2 với license key. IDA decompile thấy trả về `int` và được so sánh với literal `17` (`0x11`) tại caller.

**Lý do patch**: offline_PBKDF2 nhận license key → chạy PBKDF2 → trả về số vòng lặp hoặc kết quả hash encode. Giá trị `17` là "magic number" mà license validator chấp nhận là "license hợp lệ". Hardcode return 17 = luôn pass.

**Lưu ý**: Không phải function `17` nào cũng đúng — phải kiểm tra caller để xác nhận giá trị so sánh. Ở đây caller so sánh `result == 17`.

---

### 2. `offline_PBKDF2` — arm64e | FAT+0x3B0CA8

**Patch**: `20 02 80 52 C0 03 5F D6` → `MOV W0,#17; RET`  
(overwrite PACIBSP tại byte 0)

**Cách tìm**: arm64e slice của cùng symbol. Offset = arm64e slice base (0x2A8000) + delta từ arm64 function (đã điều chỉnh layout arm64e).

**Lưu ý**: Bytes gốc tại offset này là `7F 23 03 D5` (PACIBSP) — xác nhận đây là function start arm64e.

---

### 3. `lc_verify` — arm64 | FAT+0x11E21C

**IDA name**: `sub_11A21C`  
**Patch**: `20 00 80 52 C0 03 5F D6` → `MOV W0,#1; RET`

**Cách tìm**: Cross-reference từ startup constructor. Constructor gọi một chuỗi check functions; hàm này là lớp verify trạng thái license tổng thể sau PBKDF2. IDA cho thấy nó trả về `bool`; caller check `if (!lc_verify()) { abort_or_exit(); }`.

**Lý do patch**: Return `1` = "license valid" → caller tiếp tục bình thường.

---

### 4. `lc_verify` — arm64e | FAT+0x3C8EF0

**IDA name**: `sub_120EF0`  
**Patch**: `20 00 80 52 C0 03 5F D6` → `MOV W0,#1; RET`  
(overwrite PACIBSP)

---

### 5. `expiry_gate` — arm64 | FAT+0x108278

**IDA name**: `sub_104278`  
**Patch**: `20 00 80 52 C0 03 5F D6` → `MOV W0,#1; RET`

**Cách tìm**: Tìm string "expir" hoặc date-comparison logic trong IDA. Function này compare timestamp hiện tại với expiry date trong license. Return `1` = "chưa hết hạn".

**Lưu ý**: Function này có thể bị nhầm với một function date-util generic — xác nhận bằng cách trace caller: caller dùng kết quả để skip/enable license-expired popup.

---

### 6. `expiry_gate` — arm64e | FAT+0x3B2670

**IDA name**: `sub_10A670`  
**Patch**: `20 00 80 52 C0 03 5F D6` → `MOV W0,#1; RET`  
(overwrite PACIBSP)

---

### 7. `sub_825DC` periodic check — arm64 | FAT+0x865DC

**Patch**: `1F 20 03 D5 C0 03 5F D6` → `NOP; RET`

**Cách tìm**: Tìm `arc4random_uniform` xref trong IDA. Function `sub_81FB8` scheduler gọi `arc4random_uniform(0x15)` để tạo delay ngẫu nhiên 43–63 giây trước khi dispatch `sub_825DC`. Trace từ scheduler → target.

**Lý do patch**: `sub_825DC` chạy inline PBKDF2 lần nữa ở runtime. Nếu fail → gọi `sub_82928` hiển thị toast `[F] TOUCH: Liên hệ iOSAutomate để kích hoạt, cảm ơn` rồi kill script sau 5 giây.

**Patch dùng NOP;RET** (không phải MOV W0,#0;RET) vì function này `void` — return value không có ý nghĩa; điều quan trọng là early return để skip toàn bộ body.

**Lưu ý quan trọng**: Arm64 chỉ có 1 instance tại 0x865DC. Arm64e có **2 instance** (xem #8 và #9).

---

### 8. `sub_825DC` — arm64e #1 | FAT+0x2BD068

**Patch**: `1F 20 03 D5 C0 03 5F D6` → `NOP; RET` (overwrite PACIBSP)

**Tại sao có 2 instance arm64e?** Compiler arm64e tạo ra 2 bản của cùng function ở 2 địa chỉ khác nhau — một được schedule timer, một được inline hoặc gọi trực tiếp. Cả 2 đều phải patch; nếu miss 1, game over sau ~1 phút.

**Cách tìm instance #2**: Sau khi tìm #1, tìm tiếp cùng prologue trong arm64e slice. Cả 2 cách: search bytes `7F 23 03 D5` + pattern bytes kế tiếp, hoặc search cross-ref từ `sub_81FB8` arm64e equivalent.

---

### 9. `sub_825DC` — arm64e #2 | FAT+0x2BD230

**Patch**: `1F 20 03 D5 C0 03 5F D6` → `NOP; RET` (overwrite PACIBSP)

Offset cách #1 chỉ 0x1C8 bytes (392 bytes). Kiểm tra bằng cách compare prologue bytes sau PACIBSP.

---

### 10. `sub_102A5C` master license gate — arm64 | FAT+0x106A5C

**Patch**: `00 00 80 52 C0 03 5F D6` → `MOV W0,#0; RET`

**Cách tìm**: Tìm function được gọi từ nhiều nơi với result check kiểu `if (!sub_102A5C()) { skip_license_check(); }`. Trong IDA, function này có nhiều caller: `sub_825DC`, `sub_834D8`, `sub_84148`, `sub_16464`, `sub_E9028`, `sub_19460`.

**Logic function**: Kiểm tra "consistency" của trạng thái license — true nếu state nhất quán (licensed hoặc unlicensed một cách rõ ràng), false nếu state bị tamper/inconsistent.

**Tại sao return 0 (false)?**  
Khi `sub_102A5C` trả về `false` (inconsistent), callers skip license check và gọi `sub_102CF4` (clean completion path). Đây là behavior "no license check needed" — vì state đã bị detect là tampered, hệ thống fallback về "allow" thay vì "deny".

> **Ngược lại với trực giác**: Return `false` = "tampered/inconsistent" = callers bỏ qua kiểm tra. Return `true` = "consistent" = callers chạy kiểm tra bình thường. Muốn bypass thì return `false`.

**Quan trọng nhất**: `sub_102A5C` được hook vào Lua VM qua `sub_19460`. `sub_19460` fire mỗi ~256 Lua VM instructions sau timeout 45–60 giây. Nếu không patch `sub_102A5C`, `luaL_error("stopped")` được gọi → Lua script crash ở giữa chừng.

---

### 11. `sub_102A5C` — arm64e | FAT+0x3B0E50

**Patch**: `00 00 80 52 C0 03 5F D6` → `MOV W0,#0; RET` (overwrite PACIBSP)

**Cách tìm arm64e offset**: Tìm instruction `MOV W?, #161` (`0xA1 = 0xA1`) và `MOV W?, #187` (`0xBB`) trong vòng 200 bytes — đây là hai magic constants xuất hiện trong body của `sub_102A5C`. Scan arm64e __text cho cả 2 pattern → tìm function enclosing.

---

## HTML Blob Patch

**Không phải license patch nhưng included trong PoC.**

Dylib nhúng toàn bộ Lua IDE HTML (691 KB decompressed) dưới dạng raw deflate stream với fake gzip header.

**Cấu trúc blob**:
```
1F 8B <10-byte gzip header> "PC_IDE_obfs.html\0" <raw deflate data> <CRC32 4B> <ISIZE 4B>
```

**Cách tìm**: Search binary cho string `PC_IDE_obfs.html`. Walk backwards để tìm `1F 8B` = gzip magic. Skip header và null-terminated filename → deflate data bắt đầu.

**Cách decompress**: `zlib.decompress(data, wbits=-15)` (raw deflate, không phải gzip).

**Cách recompress**: `zlib.compressobj(level=8, method=zlib.DEFLATED, wbits=-15)`.  
> **Phải dùng level=8, không phải 9**: Level 9 tạo output lớn hơn slot ban đầu trong roothide binary (margin chỉ còn 10 bytes). Level 8 fit an toàn.

**Thay đổi trong HTML**:
- Xóa ` onclick="showGiftActivatePopup()"` khỏi `#licActiveKeyBtn`
- Thay `🔑 Active Key` → `powered by @yukoDotMoe`

Blob xuất hiện **4 lần** trong FAT (arm64 + arm64e trong cả rootless + roothide) — function `patch_html_blob()` loop scan để patch tất cả.

---

## Tóm tắt offset table

| # | Function | arm64 FAT | arm64e FAT (PACIBSP) | arm64e patch at | Patch bytes |
|---|---|---|---|---|---|
| 1 | offline_PBKDF2 | 0x1069DC | 0x3B0CA8 | **0x3B0CAC** | `20 02 80 52 FF 0B 5F D6` |
| 2 | lc_verify | 0x11E21C | 0x3C8EF0 | **0x3C8EF4** | `20 00 80 52 FF 0B 5F D6` |
| 3 | expiry_gate | 0x108278 | 0x3B2670 | **0x3B2674** | `20 00 80 52 FF 0B 5F D6` |
| 4 | sub_825DC | 0x865DC | 0x2BD068 | **0x2BD06C** | `1F 20 03 D5 FF 0B 5F D6` |
| 5 | sub_825DC #2 | *(only 1)* | 0x2BD230 | **0x2BD234** | `1F 20 03 D5 FF 0B 5F D6` |
| 6 | sub_102A5C | 0x106A5C | 0x3B0E50 | **0x3B0E54** | `00 00 80 52 FF 0B 5F D6` |

arm64 patch bytes: RET = `C0 03 5F D6`. arm64e patch bytes: RETAB = `FF 0B 5F D6`.  
Tổng: 11 patches (5 arm64 + 6 arm64e). Mỗi patch 8 bytes.

---

## Những gì KHÔNG cần patch

- **sub_81FB8 scheduler**: Chỉ cần stop `sub_825DC` là đủ — scheduler vẫn chạy nhưng gọi vào hàm đã NOP;RET.
- **sub_82928 toast displayer**: Không được gọi vì sub_825DC đã return sớm.
- **Network license check**: iOSAutomate không có auto-update hay live license check qua network (đã verify: không tìm thấy `latestVersion`, `checkUpdate`, `autoUpdate` patterns trong binary).
- **Constructor (InitFunc_0)**: Không cần patch — chỉ khởi tạo module, không crash khi license sai. Crash patch chỉ dùng cho PoC responsible disclosure (đã removed ở v1.5.3-5).

---

## Checklist build

```
[ ] Source: com.fn.rh.iOSAutomate-1.5.3-3-roothide-iphoneos-arm64e.deb
[ ] Script: make_poc_rh_main_deb.py
[ ] 11 patches applied (verify console output)
[ ] HTML blob patched (verify "HTML blob FAT+0x..." in output)
[ ] Version: 1.5.3-5+poc
[ ] Control: Depends/preinst/postinst = original (không thêm gì)
[ ] Output: com.fn.rh.iOSAutomate_poc-1.5.3-5-roothide-iphoneos-arm64e.deb
```
