#!/usr/bin/env python3
"""
iOSAutomate Roothide License Bypass PoC Patcher (Main Tweak)
-------------------------------------------------------------
Patches all client-side license checks in the main tweak dylib (v1.5.3-3, FAT arm64/arm64e).
Source: com.fn.rh.iOSAutomate-1.5.3-3-roothide-iphoneos-arm64e.deb

Patch table (all FAT file offsets, 8-byte patches):
  ARM64 slice (base FAT+0x4000, __TEXT vmaddr=0) - no PACIBSP on arm64:
    offline_PBKDF2 (_ws_3c03af885e89f55e) FAT+0x1069DC -> MOV W0,#17; RET
    lc_verify      (sub_11A21C)           FAT+0x11E21C -> MOV W0,#1;  RET
    expiry_gate    (sub_104278)           FAT+0x108278 -> MOV W0,#1;  RET
  ARM64E slice (base FAT+0x2A8000, __TEXT vmaddr=0) - all start with PACIBSP -> overwrite:
    offline_PBKDF2 (_ws_3c03af885e89f55e) FAT+0x3B0CA8 -> MOV W0,#17; RET
    lc_verify      (sub_120EF0)           FAT+0x3C8EF0 -> MOV W0,#1;  RET
    expiry_gate    (sub_10A670)           FAT+0x3B2670 -> MOV W0,#1;  RET
"""

import struct, io, tarfile, os, sys, time, hashlib, zlib, binascii
sys.stdout.reconfigure(encoding='utf-8')
try:
    import zstandard as zstd
    HAVE_ZST = True
except ImportError:
    HAVE_ZST = False

SOURCE_DEB = r"C:\Users\Hello\Downloads\iosautomate\com.fn.rh.iOSAutomate-1.5.3-3-roothide-iphoneos-arm64e.deb"
OUTPUT_DEB = r"C:\Users\Hello\Downloads\iosautomate\com.fn.rh.iOSAutomate_poc-1.5.3-16-roothide-iphoneos-arm64e.deb"

PACIBSP = bytes.fromhex("7f2303d5")

# MOV W0,#0;  RET   = 00 00 80 52  C0 03 5F D6
# MOV W0,#1;  RET   = 20 00 80 52  C0 03 5F D6
# MOV W0,#17; RET   = 20 02 80 52  C0 03 5F D6
# NOP; RET           = 1F 20 03 D5  C0 03 5F D6
# MOV W0,#0;  RETAB = 00 00 80 52  FF 0B 5F D6
# MOV W0,#1;  RETAB = 20 00 80 52  FF 0B 5F D6
# MOV W0,#17; RETAB = 20 02 80 52  FF 0B 5F D6
# NOP; RETAB         = 1F 20 03 D5  FF 0B 5F D6
#
# ARM64E strategy: keep PACIBSP at +0 (so LR gets signed), patch at +4 with RETAB.
# This correctly pairs PACIBSP→RETAB and satisfies iOS 16+ PAC enforcement on A12+.
# Overwriting PACIBSP + using plain RET (old approach) can misfire when iOS enforces
# authenticated returns or when a caller uses BLRAB (which signs LR before the call).
ARM64E_SLICE_OFF = 0x2A8000  # FAT offset where arm64e slice begins

# v1.5.3-12: CORRECT arm64e patches. Root cause found via IDA workflow analysis.
#
# CRITICAL DISCOVERY: lc_verify (sub_120EF0, vmaddr 0x120EF0) has ZERO callers in
# the arm64e slice. Every patch in v1.5.3-9/10/11 targeted dead code. The binary never
# calls lc_verify; it uses a completely independent license mechanism:
#
# PRIMARY BOOTLOOP: sub_7E78 (30s background timer, stru_2210E8 invoke at vmaddr 0x7E78)
#   Reads com.apple.keyexp_cachebadge.plist key "d" (Unix expiry timestamp).
#   When d > 0 AND d > current_time (= valid license): downloads .deb packages from
#   cloneappx.com (a1.deb-d2.deb), installs them via dpkg, then calls
#   ws_920826525635c026("launchctl reboot userspace") — kills all userspace.
#   SpringBoard restarts -> 30s timer fires again -> permanent bootloop.
#   FIX: patch CBZ W8 at vmaddr 0x819C to unconditional B, skipping the entire block.
#   Defense-in-depth: also NOP the sleep(10) and launchctl-reboot call sites.
#
# SECONDARY CRASH: sub_78FC (1s main-queue timer, stru_221068 invoke at vmaddr 0x78FC)
#   Also calls sub_7924 (same IOHIDEventSystemClientCreate null-deref crash) but fires
#   at T+1s — BEFORE the 3s timer. This was the actual remaining crash source after
#   v1.5.3-12, since we only patched the 3s call at 0x7AB0 but not the 1s call at 0x7914.
#   sub_78FC body: PACIBSP; STR a1; STR a1; BL sub_7924 (vmaddr 0x7914); RETAB.
#   FIX (v1.5.3-13): NOP the BL sub_7924 at vmaddr 0x7914 inside sub_78FC.
#
# TERTIARY CRASH (existing fix): sub_7A98 (3s main-queue timer, stru_221088)
#   Same sub_7924 crash path, patched in v1.5.3-12 at vmaddr 0x7AB0.
#
# Verified original bytes from rh_main.dylib (FAT file):
#   FAT+0x2B019C: 68 00 00 34  (CBZ W8, vmaddr+12 → download block)
#   FAT+0x2B0A18: b0 9a 06 94  (BL vmaddr 0x1AF4D8 = sleep)
#   FAT+0x2B0A28: de 60 04 94  (BL vmaddr 0x120DA0 = ws_920826525635c026)
#   FAT+0x2AF914: 04 00 00 94  (BL vmaddr 0x7924 = IOHIDEventSystemClient, in sub_78FC 1s timer)
#   FAT+0x2AFAB0: 9d ff ff 97  (BL vmaddr 0x7924 = IOHIDEventSystemClient, in sub_7A98 3s timer)
PATCHES = [
    # ARM64 — all 5 license bypass patches (no PACIBSP, plain RET)
    (0x1069DC, bytes.fromhex("20028052C0035FD6"), "arm64  offline_PBKDF2  _ws_3c03af885e89f55e -> MOV W0,#17; RET"),
    (0x11E21C, bytes.fromhex("20008052C0035FD6"), "arm64  lc_verify       sub_11A21C          -> MOV W0,#1;  RET"),
    (0x108278, bytes.fromhex("20008052C0035FD6"), "arm64  expiry_gate     sub_104278          -> MOV W0,#1;  RET"),
    (0x865DC,  bytes.fromhex("1F2003D5C0035FD6"), "arm64  sub_825DC periodic lc check        -> NOP; RET"),
    (0x106A5C, bytes.fromhex("00008052C0035FD6"), "arm64  sub_102A5C (lc gate: Lua+hooks)     -> MOV W0,#0; RET"),
    # ARM64E — sub_7E78 (30s timer): patch CBZ -> B to skip download+reboot block entirely
    # CBZ W8 at 0x819C jumps to 0x81A8 (download block) when W8=0 (license valid plist key d>now)
    # Replace with B #8 (imm26=2) -> unconditional branch to 0x81A4 (skip-block epilogue)
    (0x2B019C, bytes.fromhex("02000014"), "arm64e sub_7E78 0x819C CBZ W8 -> B #8 (skip download+reboot block)"),
    # ARM64E — sub_7E78 defense-in-depth: NOP sleep(10) and launchctl-reboot call sites
    (0x2B0A18, bytes.fromhex("1F2003D5"), "arm64e sub_7E78 0x8A18 BL sleep(10) -> NOP"),
    (0x2B0A28, bytes.fromhex("1F2003D5"), "arm64e sub_7E78 0x8A28 BL ws_920826525635c026('launchctl reboot userspace') -> NOP"),
    # ARM64E — sub_78FC (1s main-queue timer): NOP BL sub_7924 at vmaddr 0x7914
    # sub_78FC is stru_221068's invoke; fires 1s after sub_7538 via dispatch_after(1s, main_q).
    # sub_7924: dlopen IOKit → IOHIDEventSystemClientCreate(kCFAllocatorDefault) with NO null check
    # → if NULL: CFRelease(NULL) at vmaddr 0x7A80 → SIGBUS. This 1s crash was the surviving
    # bootloop source after v1.5.3-12 (which only patched the 3s call at 0x7AB0).
    # Original: 04 00 00 94 (BL sub_7924 = BL +4 instructions)
    (0x2AF914, bytes.fromhex("1F2003D5"), "arm64e sub_78FC 0x7914 BL sub_7924 -> NOP (1s timer: prevent CFRelease NULL at T+1s)"),
    # ARM64E — sub_7A98 (3s main-queue timer): NOP BL sub_7924 to prevent CFRelease(NULL) crash
    # sub_7924 calls IOHIDEventSystemClientCreate() with no null check; patched in v1.5.3-12
    (0x2AFAB0, bytes.fromhex("1F2003D5"), "arm64e sub_7A98 0x7AB0 BL sub_7924 -> NOP (3s timer: prevent CFRelease NULL crash)"),
    # ARM64E — sub_100758 (IOHIDDigitizerEvent dispatcher): NOP IOHIDEventSystemClientDispatchEvent
    # sub_7538 (init) calls ws_3900e13f8c2fb537 which immediately dispatches stru_2235F0 to a
    # background queue. stru_2235F0 invoke = sub_1006C0 -> sub_100758. Inside sub_100758:
    #   dispatch_once(sub_1007FC): qword_28B1E8 = IOHIDEventSystemClientCreate(kCFAllocatorDefault)
    # NO null check. If IOHIDEventSystemClientCreate returns NULL (entitlement issue on roothide
    # arm64e), then: IOHIDEventSystemClientDispatchEvent(NULL, event) at vmaddr 0x1007E4 -> CRASH.
    # This fires AT T+0 in background queue (milliseconds after SpringBoard loads) -> fast bootloop
    # with NO crash logs. This was the root cause surviving all previous patches.
    # FIX: NOP the IOHIDEventSystemClientDispatchEvent call inside sub_100758 (affects all callers).
    # Original: 61 b7 02 94 (BL IOHIDEventSystemClientDispatchEvent stub)
    (0x3A87E4, bytes.fromhex("1F2003D5"), "arm64e sub_100758 0x1007E4 BL IOHIDEventSystemClientDispatchEvent -> NOP (T+0 bg: prevent NULL dispatch crash)"),
    # ARM64E v1.5.3-15 PATCH A — sub_100758+4: RETAB early-exit (vmaddr 0x10075C, FAT+0x3A875C)
    # Root cause of surviving bootloop: sub_1007FC (dispatch_once handler) calls
    # IOHIDEventSystemClientCreate() which ITSELF CRASHES on roothide arm64e (entitlement/sandbox
    # restriction on A12, iOS 16.5.1). The v1.5.3-14 NOP at 0x1007E4 only killed the downstream
    # IOHIDEventSystemClientDispatchEvent call — it did NOT prevent IOHIDEventSystemClientCreate
    # inside dispatch_once (sub_1007FC) from being called. That call THROWS, propagating through
    # dispatch_once back to the background thread -> uncaught exception -> SpringBoard crash -> loop.
    # sub_100758 has 2 direct callers: vmaddr 0x1001C0 (in sub_100004, 9 callers) and vmaddr
    # 0x100748 (in sub_1006C0, dispatched via dispatch_async). Converting sub_100758 to an
    # immediate return (PACIBSP; RETAB) kills ALL paths through it at one site.
    # Strategy: keep PACIBSP at +0 (vmaddr 0x100758), patch +4 (vmaddr 0x10075C) with RETAB.
    # PACIBSP signs LR; RETAB authenticates and returns. Correct arm64e PAC pair.
    # Original at 0x10075C: ff c3 00 d1  (SUB SP, SP, #0x30 — stack frame setup, now bypassed)
    (0x3A875C, bytes.fromhex("FF0F5FD6"), "arm64e sub_100758 0x10075C SUB SP->RETAB: early-exit kills ALL IOHIDClient paths (dispatch_once sub_1007FC never runs)"),
    # ARM64E v1.5.3-15 PATCH B — ws_3900e13f8c2fb537: NOP dispatch_async (vmaddr 0x1006A8, FAT+0x3A86A8)
    # Defense-in-depth: sub_1006C0 (creates DigitizerEvent + calls sub_100758) is launched via
    # dispatch_async(global_queue, stru_2235F0) called from ws_3900e13f8c2fb537, which is called
    # synchronously from sub_7538 (SpringBoard init). NOP'ing this dispatch_async prevents
    # sub_1006C0 from ever being enqueued, so sub_100758 is never reached via the async path.
    # Combined with PATCH A, all IOHIDClient code paths are eliminated.
    # Original: d8 b8 02 94  (BL vmaddr 0x1AEA08 = dispatch_async stub)
    (0x3A86A8, bytes.fromhex("1F2003D5"), "arm64e ws_3900 0x1006A8 BL dispatch_async -> NOP: prevent sub_1006C0 async dispatch (defense-in-depth)"),

    # ── v1.5.3-16 NEW PATCHES ──────────────────────────────────────────────────────────────────
    #
    # BOOTLOOP ROOT CAUSE (surviving after v1.5.3-15): two dedicated reboot wrappers and one
    # additional IOHIDEventSystemClientDispatchEvent(NULL) path.
    #
    # PATCH C — system("reboot") wrapper RETAB (vmaddr 0xB45D4, FAT+0x35C5D4)
    #   Function at 0xB45D4: PACIBSP; SUB SP; ... ADRP X8,0x1C2000; ADD X0,X8,#0x160; BL system()
    #   ADD X0,X8,#0x160 decodes Rd=0, Rn=8, imm=0x160 -> X0 = &"reboot" (string at vmaddr 0x1C2160)
    #   system("reboot") causes an immediate kernel reboot, producing a hard bootloop.
    #   No direct BL callers in __TEXT (called exclusively via heap-allocated block invoke or
    #   function pointer from the ws scripting engine). Patch: RETAB at +4 (vmaddr 0xB45D8).
    #   Original at 0xB45D8: ff c3 00 d1  (SUB SP, SP, #0x30)
    (0x35C5D8, bytes.fromhex("FF0F5FD6"), "arm64e 0xB45D8 SUB SP->RETAB: no-op system(reboot) wrapper [v1.5.3-16]"),

    # PATCH D — system("killall -9 SpringBoard") wrapper RETAB (vmaddr 0xB4604, FAT+0x35C604)
    #   Function at 0xB4604: PACIBSP; SUB SP; ... ADRP X8,0x1C2000; ADD X0,X8,#0x170; BL system()
    #   ADD X0,X8,#0x170 -> X0 = &"killall -9 SpringBoard" (string at vmaddr 0x1C2170)
    #   Kills SpringBoard process -> launchd restarts it -> tweak re-injects -> crash loop.
    #   Same indirect-call pattern as PATCH C. Patch: RETAB at +4 (vmaddr 0xB4608).
    #   Original at 0xB4608: ff c3 00 d1  (SUB SP, SP, #0x30)
    (0x35C608, bytes.fromhex("FF0F5FD6"), "arm64e 0xB4608 SUB SP->RETAB: no-op system(killall -9 SpringBoard) wrapper [v1.5.3-16]"),

    # PATCH E — IOHIDEventSystemClientDispatchEvent(NULL) in func 0x4C33C (FAT+0x2F433C)
    #   Second unpatched dispatch site at vmaddr 0x4C714 (FAT+0x2F4714). This function takes
    #   float touch coordinates, builds an IOHIDDigitizerEvent, then loads the global
    #   IOHIDEventSystemClient ptr (which is NULL because sub_100758 is RETAB'd and
    #   sub_1007FC/IOHIDEventSystemClientCreate never run), and calls DispatchEvent(NULL, event).
    #   Dispatching to NULL => EXC_BAD_ACCESS, crashing SpringBoard -> bootloop.
    #   Callers are in funcs 0x24D04 and 0x24F38 (both called via indirect/block mechanism).
    #   NOP the BL at 0x4C714; the function then proceeds to CFRelease the event and RETAB safely.
    #   Original at 0x2F4714: 95 87 05 94  (BL IOHIDEventSystemClientDispatchEvent stub)
    (0x2F4714, bytes.fromhex("1F2003D5"), "arm64e 0x4C714 BL IOHIDEventSystemClientDispatchEvent->NOP: prevent NULL dispatch in touch path [v1.5.3-16]"),

    # PATCH F — generic system() executor at 0x13DF7C RETAB (FAT+0x3E5F7C)
    #   Function at 0x13DF7C: PACIBSP; sets up stack; calls some helper at 0x126914; then loads
    #   original X0 arg and calls system(X0). Argument is caller-provided (command string).
    #   No direct BL callers in __TEXT (indirect call). If called with "reboot" or similar,
    #   causes reboot. RETAB at +4 prevents any execution.
    #   Original at 0x13DF80: ff c3 00 d1  (SUB SP, SP, #0x30)
    (0x3E5F80, bytes.fromhex("FF0F5FD6"), "arm64e 0x13DF80 SUB SP->RETAB: no-op dynamic system() executor func 0x13DF7C [v1.5.3-16]"),

    # PATCH G — generic system() executor at 0x176A64 RETAB (FAT+0x41EA64)
    #   Function at 0x176A64: PACIBSP; calls helpers at 0x1593F8 and 0x1AE7A8; then calls
    #   system(X0) with caller-provided command. Same indirect-call pattern. RETAB at +4.
    #   Original at 0x176A68: ff c3 00 d1  (SUB SP, SP, #0x30)
    (0x41EA68, bytes.fromhex("FF0F5FD6"), "arm64e 0x176A68 SUB SP->RETAB: no-op dynamic system() executor func 0x176A64 [v1.5.3-16]"),
]


def parse_ar(raw):
    assert raw[:8] == b"!<arch>\n", "Not an ar archive"
    entries, pos = [], 8
    while pos + 60 <= len(raw):
        name  = raw[pos:pos+16].rstrip(b" /")
        mtime = raw[pos+16:pos+28]
        uid   = raw[pos+28:pos+34]
        gid   = raw[pos+34:pos+40]
        mode  = raw[pos+40:pos+48]
        size  = int(raw[pos+48:pos+58].strip())
        assert raw[pos+58:pos+60] == b"`\n", f"bad ar header at {pos:#x}"
        data  = raw[pos+60 : pos+60+size]
        entries.append(dict(name=name.decode(), mtime=mtime,
                            uid=uid, gid=gid, mode=mode, data=data))
        pos += 60 + size + (size & 1)
    return entries

def build_ar(entries):
    out = b"!<arch>\n"
    ts  = str(int(time.time())).encode()
    for e in entries:
        data = e["data"]
        name = (e["name"].encode() + b"/").ljust(16)[:16]
        hdr  = (name
              + e.get("mtime", ts).ljust(12)[:12]
              + e.get("uid",   b"0").ljust(6)[:6]
              + e.get("gid",   b"0").ljust(6)[:6]
              + e.get("mode",  b"100644").ljust(8)[:8]
              + str(len(data)).encode().ljust(10)[:10]
              + b"`\n")
        out += hdr + data
        if len(data) & 1:
            out += b"\x00"
    return out

def _decompress(raw, name):
    if name.endswith(".zst"):
        if not HAVE_ZST:
            raise RuntimeError("pip install zstandard")
        return zstd.ZstdDecompressor().decompress(raw, max_output_size=256*1024*1024)
    if name.endswith(".gz"):
        import gzip; return gzip.decompress(raw)
    if name.endswith(".xz"):
        import lzma; return lzma.decompress(raw)
    if name.endswith(".bz2"):
        import bz2; return bz2.decompress(raw)
    return raw

def read_tar(raw, name):
    unc = _decompress(raw, name)
    tf  = tarfile.open(fileobj=io.BytesIO(unc), mode="r:")
    members = tf.getmembers()
    fdata   = {m.name: (tf.extractfile(m).read() if m.isfile() else None) for m in members}
    tf.close()
    return members, fdata

def write_tar_gz(members, fdata, overrides=None):
    overrides = overrides or {}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for m in members:
            ti = tarfile.TarInfo(m.name)
            for attr in ("mode","uid","gid","uname","gname","mtime","type","linkname"):
                setattr(ti, attr, getattr(m, attr))
            if m.name in overrides:
                payload = overrides[m.name]
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
            elif m.isfile():
                data_bytes = fdata.get(m.name) or b''
                ti.size = len(data_bytes)
                tf.addfile(ti, io.BytesIO(data_bytes))
            else:
                ti.size = 0
                tf.addfile(ti)
    return buf.getvalue()

def tar_append(members, fdata, name, payload, mode=0o755):
    members = [m for m in members if m.name != name]
    ti = tarfile.TarInfo(name)
    ti.mode = mode; ti.uid = 0; ti.gid = 0
    ti.uname = "root"; ti.gname = "wheel"
    ti.mtime = int(time.time()); ti.type = tarfile.REGTYPE
    members.append(ti)
    fdata[name] = payload
    return members, fdata

def patch_html_blob(data, max_fat_offset=None):
    """Remove onclick showGiftActivatePopup and replace key emoji text in embedded IDE HTML blobs.
    max_fat_offset: if set, skip any blob whose gz_start >= this offset (use to exclude arm64e slice).
    """
    old_onclick = b' onclick="showGiftActivatePopup()"'
    old_text    = "\U0001f511 Active Key".encode("utf-8")
    new_text    = b"powered by @yukoDotMoe"
    patched = 0
    search_from = 0
    while True:
        idx = data.find(b"PC_IDE_obfs.html", search_from)
        if idx == -1:
            break
        gz_start = None
        for back in range(1, 200):
            if data[idx-back:idx-back+2] == b'\x1f\x8b':
                gz_start = idx - back
                break
        if gz_start is None:
            search_from = idx + 1
            continue
        # Skip blobs in arm64e slice to leave it untouched
        if max_fat_offset is not None and gz_start >= max_fat_offset:
            print(f"  HTML blob FAT+0x{gz_start:X}: SKIPPED (arm64e slice, >= 0x{max_fat_offset:X})")
            search_from = idx + 1
            continue
        pos = gz_start + 10
        while data[pos] != 0:
            pos += 1
        pos += 1
        deflate_start = pos
        d = zlib.decompressobj(wbits=-15)
        html = b""
        p = deflate_start
        while True:
            chunk = bytes(data[p:p+65536])
            if not chunk:
                break
            html += d.decompress(chunk)
            p += 65536
            if d.eof:
                unused = len(d.unused_data)
                deflate_end = p - 65536 + (65536 - unused)
                break
        html_new = html.replace(old_onclick, b"", 1).replace(old_text, new_text, 1)
        c = zlib.compressobj(level=8, method=zlib.DEFLATED, wbits=-15)
        compressed = c.compress(html_new) + c.flush()
        orig_size = deflate_end - deflate_start
        assert len(compressed) <= orig_size, f"HTML recompression too large: {len(compressed)} > {orig_size}"
        data[deflate_start:deflate_end] = compressed + bytes(orig_size - len(compressed))
        struct.pack_into('<I', data, deflate_end,   binascii.crc32(html_new) & 0xFFFFFFFF)
        struct.pack_into('<I', data, deflate_end+4, len(html_new) & 0xFFFFFFFF)
        print(f"  HTML blob FAT+0x{deflate_start:X}: onclick removed, text rebranded ({len(html)}->{len(html_new)} B, cmp {len(compressed)}/{orig_size})")
        patched += 1
        search_from = deflate_end + 8
    return patched


def patch_dylib(raw):
    data  = bytearray(raw)
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic != 0xCAFEBABE:
        raise ValueError(f"Expected FAT CAFEBABE, got 0x{magic:08X}")
    print(f"  FAT Mach-O: {len(data):,} B  SHA256={hashlib.sha256(raw).hexdigest()[:16]}...")

    for offset, patch, label in PATCHES:
        n = len(patch)
        before = bytes(data[offset:offset+n])
        # sanity checks for arm64e patches
        if "arm64e" in label and "CBZ" in label:
            # verify CBZ W8 at this location (original 68 00 00 34)
            assert before == bytes.fromhex("68000034"), \
                f"Expected CBZ W8 (68 00 00 34) at FAT+0x{offset:X}, got {before.hex()}"
        data[offset:offset+n] = patch
        print(f"  {label}")
        print(f"    FAT+0x{offset:08X}  {before.hex(' ')} -> {patch.hex(' ')}")

    n = patch_html_blob(data, max_fat_offset=ARM64E_SLICE_OFF)
    if n == 0:
        print("  WARNING: no HTML blobs found/patched")

    patched = bytes(data)
    print(f"  Patched SHA256={hashlib.sha256(patched).hexdigest()[:16]}...")
    return patched


def main():
    print("=== iOSAutomate Roothide Main Tweak PoC Patcher ===")
    print(f"Source: {SOURCE_DEB}\n")

    raw     = open(SOURCE_DEB, "rb").read()
    entries = parse_ar(raw)

    print(".deb ar contents:")
    for e in entries:
        print(f"  {e['name']:30s}  {len(e['data']):>10,} B")

    data_e = next(e for e in entries if e["name"].startswith("data.tar"))
    ctrl_e = next(e for e in entries if e["name"].startswith("control.tar"))

    dc = data_e["name"]
    print(f"\ndata.tar compression: {dc.split('.')[-1]}")

    d_mem, d_fd = read_tar(data_e["data"], dc)
    print("\ndata.tar contents:")
    dylib_keys = []
    for m in d_mem:
        sz = f"{len(d_fd[m.name]):>10,} B" if m.isfile() else "     <dir>"
        print(f"  {m.name:80s}  {sz}")
        if m.isfile() and m.name.endswith(".dylib") and "DynamicLibraries" in m.name:
            dylib_keys.append(m.name)

    if not dylib_keys:
        raise RuntimeError("Could not find .dylib under DynamicLibraries in data tar")
    print(f"\nTarget dylib(s):")
    for k in dylib_keys:
        print(f"  {k}")

    print("\n=== Patching dylib(s) ===")
    d_overrides = {}
    for k in dylib_keys:
        print(f"\n--- {k} ---")
        d_overrides[k] = patch_dylib(d_fd[k])

    new_data_tar = write_tar_gz(d_mem, d_fd, d_overrides)
    main_dylib_key = dylib_keys[0]
    print(f"\nRebuilt data.tar.gz: {len(new_data_tar):>10,} B  (was {len(data_e['data']):>10,} B)")

    # Control tar
    cc = ctrl_e["name"]
    c_mem, c_fd = read_tar(ctrl_e["data"], cc)
    ctrl_key = next((k for k in c_fd if k.rstrip("/").endswith("control")), None)
    c_over = {}

    if ctrl_key and c_fd[ctrl_key]:
        lines = []
        for line in c_fd[ctrl_key].decode().splitlines():
            if line.startswith("Version:"):
                lines.append("Version: 1.5.3-16+poc")
            elif line.startswith("Depends:"):
                val = line.rstrip()
                if "oldabi" not in val:
                    val += ", oldabi"
                lines.append(val)
            else:
                lines.append(line)
        c_over[ctrl_key] = ("\n".join(lines) + "\n").encode()
        print("Updated control: Version 1.5.3-16+poc, oldabi in Depends, postinst original")
    # postinst: keep original unmodified (no ldid -S addition for this diagnostic build)

    new_ctrl_tar = write_tar_gz(c_mem, c_fd, c_over)
    print(f"Rebuilt control.tar.gz: {len(new_ctrl_tar):>10,} B")

    # Reassemble .deb
    new_entries = []
    for e in entries:
        n = e["name"]
        if   n.startswith("data.tar"):    new_entries.append(dict(e, name="data.tar.gz",    data=new_data_tar))
        elif n.startswith("control.tar"): new_entries.append(dict(e, name="control.tar.gz", data=new_ctrl_tar))
        else:                             new_entries.append(e)

    output = build_ar(new_entries)
    open(OUTPUT_DEB, "wb").write(output)

    print(f"\n=== SUCCESS ===")
    print(f"Output: {OUTPUT_DEB}")
    print(f"Size:   {len(output):,} B")
    print(f"\nPatches applied ({len(PATCHES)} total):")
    for offset, _, label in PATCHES:
        print(f"  FAT+0x{offset:08X}  {label}")
    print("\narm64e: sub_7E78 30s-timer download+reboot block neutered (CBZ->B + 2x NOP).")
    print("arm64e: sub_78FC 1s-timer BL sub_7924 NOP'd.")
    print("arm64e: sub_7A98 3s-timer BL sub_7924 NOP'd.")
    print("arm64e: sub_100758 IOHIDEventSystemClientDispatchEvent NOP'd [v1.5.3-14].")
    print("arm64e: sub_100758+4 RETAB early-exit [v1.5.3-15].")
    print("arm64e: ws_3900 dispatch_async NOP'd [v1.5.3-15].")
    print("arm64e: system(reboot) wrapper 0xB45D4 RETAB'd [v1.5.3-16 NEW].")
    print("arm64e: system(killall SpringBoard) wrapper 0xB4604 RETAB'd [v1.5.3-16 NEW].")
    print("arm64e: IOHIDEventSystemClientDispatchEvent(NULL) in 0x4C33C NOP'd at 0x4C714 [v1.5.3-16 NEW].")
    print("arm64e: generic system() executor 0x13DF7C RETAB'd [v1.5.3-16 NEW].")
    print("arm64e: generic system() executor 0x176A64 RETAB'd [v1.5.3-16 NEW].")
    print("arm64:  all 5 license functions bypassed.")


if __name__ == "__main__":
    main()
