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

import struct, io, tarfile, os, sys, time, hashlib, zlib, binascii, math
sys.stdout.reconfigure(encoding='utf-8')
try:
    import zstandard as zstd
    HAVE_ZST = True
except ImportError:
    HAVE_ZST = False

SOURCE_DEB = r"C:\Users\Hello\Downloads\iosautomate\com.fn.rh.iOSAutomate-1.5.3-3-roothide-iphoneos-arm64e.deb"
OUTPUT_DEB = r"C:\Users\Hello\Downloads\iosautomate\com.fn.rh.iOSAutomate_poc-1.5.3-40-roothide-iphoneos-arm64e.deb"

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
    # v1.5.3-40 — stop must abort the Lua VM, not turn sleep() into a zero-delay call.
    # Live Frida trace on SpringBoard showed the stop flag flip to 1, followed by
    # sub_2E448 (Lua sleep callback) returning 0 repeatedly (calls 37..103 in ~11 ms),
    # with no releaseLuaState/lua_close/worker exit before the crash. IDA confirms both
    # stop branches currently set return value 0 and jump to the epilogue. Load the
    # saved lua_State * from [X29,#-0x10] into X0, then branch to existing noreturn
    # sub_2E764, which calls luaL_error(L, "user_stopped").
    # vmaddr 0x2E4B8: LDUR X0,[X29,#-0x10]; B sub_2E764 (imm26 0xAA)
    (0x2D64B8, bytes.fromhex("A0035FF8AA000014"), "arm64e Lua sleep initial stop path -> sub_2E764 luaL_error('user_stopped') [v1.5.3-40]"),
    # vmaddr 0x2E578: LDUR X0,[X29,#-0x10]; B sub_2E764 (imm26 0x7A)
    (0x2D6578, bytes.fromhex("A0035FF87A000014"), "arm64e Lua sleep loop stop path -> sub_2E764 luaL_error('user_stopped') [v1.5.3-40]"),
    # v1.5.3-39 — globally disable toast dispatch. The v38 caller-specific NOPs did not
    # stop SpringBoard-2026-08-16-192757.ips: SpringBoard lived only ~22 seconds yet the
    # crashing main-thread stack contained 501 nested _dispatch_call_block_and_release
    # frames, with the sole tweak frame at sub_F2EC+0x21F4 (0x114E0), immediately after
    # objc_autoreleasePoolPop. _ws_show_toast always dispatch_async(main, sub_F2EC), and
    # it has many callers, so patching more individual producers would be speculative.
    # Preserve PACIBSP at 0xF1F8 and replace verified SUB SP,SP,#0x80 at +4 with RETAB.
    (0x2B71FC, bytes.fromhex("FF0F5FD6"), "arm64e _ws_show_toast 0xF1FC RETAB: globally prevent sub_F2EC main-queue accumulation [v1.5.3-39]"),
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

    # ── v1.5.3-16 PATCHES ─────────────────────────────────────────────────────────────────────
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

    # ── v1.5.3-17 NEW PATCHES ──────────────────────────────────────────────────────────────────
    #
    # ROOT CAUSE OF PERSISTENT BOOTLOOP: posix_spawn("launchctl reboot userspace") calls.
    # These are COMPLETELY DIFFERENT from system("reboot") — they call posix_spawn directly
    # with the launchctl binary as argv[0] and ["reboot", "userspace"] as arguments.
    # The v1.5.3-16 patches only covered system("reboot") wrappers and IOHIDClient crashes.
    # The bootloop was actually caused by posix_spawn(launchctl reboot userspace) calls that
    # fire automatically on startup via the daemon health-check timer.
    #
    # Discovery method: IDA arm64 analysis of rh_main.dylib, then binary scan of arm64e slice
    # for ADRP+ADD sequences loading the "reboot" string (arm64e VA=0x1C2160) in __text.
    # All 9 functions below were found by scanning FAT+0x2A8000 onwards.
    #
    # KEY: arm64e auto-reboot timer callback (equivalent of arm64 sub_F0D34):
    #   sub_F0D34 (arm64) is a timer callback for _checkDaemonAndAlertIfNeeded.
    #   When retry counter hits 0 → dismisses VC → dispatch_after(300ms) → immediately
    #   calls posix_spawn("launchctl reboot userspace") — causes hard userspace reboot.
    #   The timer fires automatically when the daemon socket check fails (which it always
    #   does in our PoC because the iOSAutomate daemon is not running).
    #   ARM64E equivalent: arm64e VA=0xF6C84 (FAT+0x39EC84).
    #   Note: orig bytes at +4 = fc 6f be a9 (STP X28,X27 frame) — NOT the usual SUB SP.

    # PATCH H: Lua reboot dispatcher (arm64e 0x2F088, like arm64 sub_2C81C)
    # strcmp("reboot") then calls posix_spawn reboot. Frame 0x80.
    # orig: ff 03 02 d1 = SUB SP, SP, #0x80
    (0x2D708C, bytes.fromhex("FF0F5FD6"), "arm64e 0x2F088+4 RETAB: Lua reboot dispatcher (strcmp 'reboot') [v1.5.3-17]"),

    # PATCH I: Lua reboot dispatcher variant (arm64e 0x2F2A8, like arm64 sub_2CA58)
    # Similar Lua dispatch. Frame 0x70.
    # orig: ff c3 01 d1 = SUB SP, SP, #0x70
    (0x2D72AC, bytes.fromhex("FF0F5FD6"), "arm64e 0x2F2A8+4 RETAB: Lua reboot dispatcher variant [v1.5.3-17]"),

    # PATCH J: posix_spawn reboot (arm64e 0x54540, equivalent arm64 sub_52028)
    # Finds launchctl path, posix_spawn(launchctl, ["reboot","userspace"]). Frame 0x1B0.
    # Called from Lua "reboot" command handler. orig: ff c3 06 d1 = SUB SP, SP, #0x1B0
    (0x2FC544, bytes.fromhex("FF0F5FD6"), "arm64e 0x54540+4 RETAB: posix_spawn(launchctl reboot userspace) Lua path [v1.5.3-17]"),

    # PATCH K: posix_spawn reboot (arm64e 0x9594C, equivalent arm64 sub_91AF4)
    # Same posix_spawn reboot, called from data block (timer/async). Frame 0x1C0.
    # orig: ff 03 07 d1 = SUB SP, SP, #0x1C0
    (0x33D950, bytes.fromhex("FF0F5FD6"), "arm64e 0x9594C+4 RETAB: posix_spawn(launchctl reboot userspace) block path [v1.5.3-17]"),

    # PATCH L: posix_spawn reboot (arm64e 0xF2714, equivalent arm64 sub_EC918)
    # resolveJBLaunchctl -> posix_spawn reboot. Called from rebootTapped UI.
    # Frame 0x70. orig: ff c3 01 d1 = SUB SP, SP, #0x70
    (0x39A718, bytes.fromhex("FF0F5FD6"), "arm64e 0xF2714+4 RETAB: posix_spawn(launchctl reboot userspace) UI path [v1.5.3-17]"),

    # PATCH M: AUTO-REBOOT TIMER CALLBACK (arm64e 0xF6C84, equivalent arm64 sub_F0D34)
    # _showDaemonDownAlert timer callback: decrements retry counter, when 0 calls
    # posix_spawn(launchctl reboot userspace) automatically — PRIMARY bootloop cause!
    # Starts with STP X28,X27 frame (not typical SUB SP), then PACIBSP.
    # orig: fc 6f be a9 = STP X28, X27, [SP, #-0x20]!
    (0x39EC88, bytes.fromhex("FF0F5FD6"), "arm64e 0xF6C84+4 RETAB: AUTO-REBOOT TIMER sub_F0D34 equivalent [v1.5.3-17]"),

    # PATCH N: Lua53 reboot dispatcher (arm64e 0x11A190, equivalent arm64 sub_113530)
    # luaL53_checklstring(L,1) == "reboot" -> calls posix_spawn reboot. Frame 0x50.
    # orig: ff 43 01 d1 = SUB SP, SP, #0x50
    (0x3C2194, bytes.fromhex("FF0F5FD6"), "arm64e 0x11A190+4 RETAB: Lua53 reboot dispatcher [v1.5.3-17]"),

    # PATCH O: Lua53 reboot dispatcher variant (arm64e 0x11A2B8)
    # Similar Lua53 dispatch. Frame 0x80.
    # orig: ff 03 02 d1 = SUB SP, SP, #0x80
    (0x3C22BC, bytes.fromhex("FF0F5FD6"), "arm64e 0x11A2B8+4 RETAB: Lua53 reboot dispatcher variant [v1.5.3-17]"),

    # PATCH P: posix_spawn reboot Lua53 path (arm64e 0x11D894, equivalent arm64 sub_116CA4)
    # posix_spawn reboot called from Lua53 "reboot" command. Frame 0x1B0.
    # orig: ff c3 06 d1 = SUB SP, SP, #0x1B0
    (0x3C5898, bytes.fromhex("FF0F5FD6"), "arm64e 0x11D894+4 RETAB: posix_spawn(launchctl reboot userspace) Lua53 path [v1.5.3-17]"),

    # ── v1.5.3-24 PATCHES ─────────────────────────────────────────────────────────────────────
    #
    # ROOT CAUSE OF "script causes safe mode after ~60s": sub_825DC periodic license check
    # arm64e — NOT patched in any prior version.
    #
    # crash log: SpringBoard-2026-08-15-202655.ips
    #   EXC_CRASH SIGBUS "Address size fault" (ESR=0x56000080, stack overflow)
    #   511 frames total — frames [15]-[510] ALL _dispatch_call_block_and_release
    #   frame [14]: img[13]=main tweak at arm64e off=0xFC44 (sub_FAD4, UIView animation setup)
    #   frame [13]: UIView._addSubview:positioned:relativeTo:
    #   frames [0-12]: UIKit trait-collection propagation → NSArray crash
    #
    # Root cause chain:
    #   sub_825DC (arm64e, periodic PBKDF2 license check, fires at ~60s, was NOT patched in arm64e)
    #   → license key absent → PBKDF2 fails
    #   → dispatch_async(main_queue, sub_82928)  [shows "TOUCH: Liên hệ iOSAutomate để kích hoạt" toast]
    #   → sub_82928 calls _ws_show_toast 3x in rapid succession
    #   → _ws_show_toast → sub_D7C0 (UIView overlay setup) → sub_FAD4
    #   → +[UIView animateWithDuration:animations:completion:] adds UIViews
    #   → _addSubview triggers synchronous trait-collection cascade (UIKit re-entrancy)
    #   → 497-deep dispatch block recursion → stack pointer exits valid VA space (arm64e)
    #   → Address size fault (SIGBUS) → SpringBoard crash → safe mode
    #
    # Also patching sub_102A5C arm64e (master license gate) to return 0:
    #   sub_825DC calls sub_102A5C() first; if it returns 0 → takes else path → sub_102CF4()
    #   (clean script finish), skipping the entire PBKDF2 check and toast path.
    #   Double-defense: even if sub_825DC runs, sub_102A5C=0 makes it exit cleanly.
    #
    # ARM64 equivalents were already patched:
    #   arm64 sub_825DC:  FAT+0x865DC  (IDA vmaddr 0x825DC) → NOP;RET  [v1.5.3-?]
    #   arm64 sub_102A5C: FAT+0x106A5C (IDA vmaddr 0x102A5C) → MOV W0,#0;RET [v1.5.3-?]
    #
    # ARM64E equivalents (arm64e slice base FAT+0x2A8000):
    #   sub_825DC  #1: vmaddr 0x15068 → FAT+0x2BD068, PACIBSP at +0, patch at +4
    #   sub_825DC  #2: vmaddr 0x15230 → FAT+0x2BD230, PACIBSP at +0, patch at +4
    #   sub_102A5C:    vmaddr 0x108E50 → FAT+0x3B0E50, PACIBSP at +0, patch at +4 with MOV W0,#0;RETAB
    #
    # PATCH Q — sub_825DC arm64e #1: RETAB at +4 (vmaddr 0x1506C, FAT+0x2BD06C)
    # PACIBSP is at FAT+0x2BD068 (kept intact). Patch the instruction at +4 with RETAB.
    # PACIBSP→RETAB pair: LR is signed then immediately authenticated+returned. Clean exit.
    (0x2BD06C, bytes.fromhex("FF0F5FD6"), "arm64e sub_825DC #1 0x1506C RETAB: periodic lc check arm64e → early return [v1.5.3-24]"),

    # PATCH R — sub_825DC arm64e #2: RETAB at +4 (vmaddr 0x15234, FAT+0x2BD234)
    # Second arm64e instance of the periodic check. Same PACIBSP+RETAB strategy.
    (0x2BD234, bytes.fromhex("FF0F5FD6"), "arm64e sub_825DC #2 0x15234 RETAB: periodic lc check arm64e (2nd) → early return [v1.5.3-24]"),

    # PATCH S — sub_102A5C arm64e: MOV W0,#0; RETAB at +4 (vmaddr 0x108E54, FAT+0x3B0E54)
    # PACIBSP at FAT+0x3B0E50 (kept). Patch +4 with MOV W0,#0 (return false=inconsistent)
    # so sub_825DC's outer `if ((sub_102A5C() & 1) != 0)` is always false → clean exit path.
    # Double-defense on top of PATCHES Q and R.
    (0x3B0E54, bytes.fromhex("00008052FF0F5FD6"), "arm64e sub_102A5C 0x108E54 MOV W0,#0;RETAB: lc gate arm64e → return 0 [v1.5.3-24]"),

    # ── v1.5.3-28 PATCHES ─────────────────────────────────────────────────────────────────────
    #
    # ROOT CAUSE OF "script still causes safe mode after ~66s" on v1.5.3-24:
    # crash log: SpringBoard-2026-08-15-210440.ips
    #   EXC_BAD_ACCESS SIGBUS KERN_PROTECTION_FAILURE at 0x0000000dbb7410a0
    #   faultingThread=2, 511 frames
    #   frame [1]: luaD_poscall at img[13] off=0x166434
    #   frames [2]-[510]: off=0x166CCC × 509 times (traversethread BL return addr)
    #
    # 9-hop recursion cycle in arm64e GC (arm64 does NOT have this):
    #   traversethread(0x166B78) → luaD_poscall(0x1663A0) → 0x1665B8 → 0x16939C →
    #   0x1694E0 → 0x169850 → 0x167158 → 0x1674C4 → 0x166E84 → traversethread
    #
    # v1.5.3-25 FAILED: NOP'd BL at traversethread 0x166CC8 (FAT+0x40ECC8).
    #   Broke Lua call-stack management — luaD_poscall never called → corrupted Lua state.
    #   Result: SIGABRT callback loop T+7s. (SpringBoard-2026-08-15-220237.ips)
    #
    # v1.5.3-26 FAILED: inline LDR+STR instead of luaD_poscall. Same corruption. T+10s.
    #   (SpringBoard-2026-08-15-230906.ips)
    #
    # v1.5.3-27 FAILED: NOP'd BL 0x1665B8 at luaD_poscall+0x90 (vmaddr 0x166430, FAT+0x40E430).
    #   luaD_poscall runs; CI restored. But 0x1665B8 (result adjuster) is never called.
    #   0x1665B8 is responsible for adjusting L->top after closure execution. Skipping it
    #   leaves L->top pointing past the results → Lua VM reads wrong TValues → type error
    #   in luaV_finishset → UIKit callback loop → SIGABRT T+22s (502 frames 0x156730).
    #   (SpringBoard-2026-08-15-235318.ips)
    #
    # CORRECT FIX (v1.5.3-28): two NOPs inside 0x1665B8 at the recursion trigger point.
    #
    #   0x1665B8 is called from luaD_poscall and adjusts L->top after closure execution.
    #   When CI->nresults < -1 (iOSAutomate custom GC signal), 0x1665B8 at 0x1666DC calls
    #   bl #0x16939c, starting the 9-hop recursion chain. The return value of 0x16939C is
    #   then stored back at [x29,#-0x10] (0x1666E0: stur x0,[x29,#-0x10]), overwriting
    #   func_obj — which the subsequent write-barrier path at 0x166704 reads as a pointer.
    #
    #   Fix 1: NOP bl #0x16939c at 0x1666DC → breaks the recursion chain.
    #   Fix 2: NOP stur x0,[x29,#-0x10] at 0x1666E0 → [x29,#-0x10] retains the original
    #     CI->func pointer (stored there by 0x1665B8's prologue at 0x1665D8 from luaD_poscall).
    #     The write-barrier path at 0x166704 (ldur x8,[x29,#-0x10]) then sees the correct
    #     func_obj = CI->func, computes a valid stack offset, and 0x1665B8 completes normally.
    #
    #   Result: 0x1665B8 completes result copying and L->top adjustment; no recursion.
    #   luaD_poscall returns; traversethread returns. GC step completes cleanly.
    #
    # Verified original bytes:
    #   FAT+0x40E6DC: 30 0b 00 94  (BL #0x16939c, imm26=0xB30, offset=+0x2CC0)
    #   FAT+0x40E6E0: a0 03 1f f8  (STUR X0, [X29, #-0x10])

    # PATCH V1 — arm64e 0x1665B8+0x124: NOP bl #0x16939c (break 9-hop GC recursion)
    # 0x1665B8 result-adjuster still fully executes; only the recursive chain is cut.
    (0x40E6DC, bytes.fromhex("1F2003D5"), "arm64e 0x1666DC NOP bl #0x16939c: break 9-hop GC recursion (0x1665B8 result-adjuster still runs normally) [v1.5.3-28]"),

    # PATCH V2 — arm64e 0x1665B8+0x128: NOP stur x0,[x29,#-0x10] (preserve func_obj)
    # After NOPing BL, X0 = L (lua_State*); without this NOP it would corrupt [x29,#-0x10].
    # With NOP: [x29,#-0x10] retains CI->func (correct pointer for write-barrier at 0x166704).
    (0x40E6E0, bytes.fromhex("1F2003D5"), "arm64e 0x1666E0 NOP stur x0,[x29,#-0x10]: preserve func_obj=CI->func for write-barrier [v1.5.3-28]"),

    # ── v1.5.3-29/30 PATCHES ──────────────────────────────────────────────────────────────────
    #
    # v1.5.3-29 attempted PATCH W1-W4: NOP traversethread calls in 0x166884 and 0x166E84.
    # WRONG — 0x166884/0x166E84 are Lua CALL OPCODE HANDLERS, not GC traversal functions.
    # NOP'ing traversethread inside them means C-closure CALL opcodes never execute the C func,
    # leaving L->top in wrong state → luaG_typeerror → luaD_throw → SIGABRT (same as v1.5.3-27).
    # Crash log: SpringBoard-2026-08-16-014133.ips: Thread 6 = luaD_throw → luaG_typeerror →
    # luaV_finishset+384 → 502× 0x156730 (luaV_execute). PATCH W1-W4 REVERTED in v1.5.3-30.
    #
    # "Stop Lua" UIKit cascade (Thread 0: 492-deep dispatch loop):
    #   crash log: SpringBoard-2026-08-16-011119.ips
    #   faultingThread=0, frame[18]=tweak@0xFBC0, frame[17]=UIKitCore._setHidden:forced:
    #   frames[19-510]=492× _dispatch_call_block_and_release
    #
    #   sub_F2EC stop-handler (toast + stop logic). Dispatch loop mechanism (IDA + crash logs):
    #
    #   STAGE 1 — QUEUE: setWindowScene: at 0xFB24 adds UIWindow to UIWindowScene.
    #     FBSceneLayerManager sees scene change → dispatch_async(mainQueue, stop_block).
    #     0xFA68: CBNZ X8, loc_FC74  ; existing-window path (skip creation)
    #     0xFA70-0xFAD8: [UIWindow alloc] + [UIWindow initWithFrame:bounds] → new UIWindow
    #     0xFAF8-0xFB04: load qword_28AE00 (UIWindowScene ptr), CBZ → skip if nil
    #     0xFB14-0xFB24: LDR X0,[SP,var_250]; LDR X1,"setWindowScene:"; BL _objc_msgSend
    #                    ← THIS QUEUES stop_block via FBSceneLayerManager dispatch_async
    #
    #   STAGE 2 — DRAIN: queued stop_block is run SYNCHRONOUSLY by UIKit drain points:
    #     a) setHidden:NO at 0xFBBC: UIKit _setHidden:forced: drains mainQueue → runs stop_block
    #        Confirmed: 011119.ips frame[17]=UIKitCore._setHidden:forced:, frame[18]=tweak@0xFBC0
    #     b) UITextField initWithFrame: at 0xFBEC: _performSystemAppearanceModifications: drains
    #        mainQueue → runs stop_block
    #        Confirmed: 024053.ips (v1.5.3-31 Y1) frame[12]=UITextField_block_invoke,
    #        frame[15]=tweak@0xFBF0, 495× _dispatch_call_block_and_release
    #
    #   v1.5.3-30 WRONG FIX: X1/X2/X3 NOP'd 0xFBEC/0xFC0C/0xFC28 — these are UITextField
    #   init calls, not UIKit scene triggers. UITextField un-init'd → addSubview: crash (015848.ips).
    #
    #   v1.5.3-31 WRONG FIX: Y1 NOP'd 0xFBBC (setHidden:NO) — removes drain point (a) but
    #   setWindowScene: STILL queues stop_block; UITextField initWithFrame: drains it → 495×
    #   recursion → CFEqual SIGBUS (024053.ips). Also breaks toast (window never shown).
    #
    #   v1.5.3-32 CORRECT FIX (Z1): NOP setWindowScene: at 0xFB24.
    #   Without setWindowScene:, UIWindow has no UIWindowScene → FBSceneLayerManager never sees it
    #   → stop_block is never queued → no drain points ever run the recursive stop_block
    #   → setHidden:NO at 0xFBBC runs cleanly (window shown without scene via pre-iOS13 path)
    #   → UITextField initWithFrame: runs cleanly (no pending queued blocks to drain)
    #
    # Verified original bytes (arm64e slice base 0x2A8000):
    #   FAT+0x2B7B24: a57d0694 (bl _objc_msgSend) ← [var_250 setWindowScene:qword_28AE00]
    #   FAT+0x2B7BBC: 7f7d0694 (bl _objc_msgSend) ← [var_250 setHidden:NO] — RESTORED (Y1 removed)

    # PATCH Z1 — NOP [UIWindow setWindowScene:] at 0xFB24 (FAT+0x2B7B24): break FBScene queue
    # setWindowScene: is what queues stop_block via FBSceneLayerManager dispatch_async.
    # Without it, UIWindow has no scene → FBSceneLayerManager never queues stop_block →
    # neither setHidden: nor UITextField init can trigger recursive dispatch.
    # setHidden:NO at 0xFBBC (Y1 REMOVED) still runs → window shown via pre-iOS13 UIScreen path.
    (0x2B7B24, bytes.fromhex("1F2003D5"), "arm64e 0xFB24 NOP bl objc_msgSend/setWindowScene: (QUEUE point: adds UIWindow to scene→FBSceneLayerManager queues stop_block; NOP breaks queue, setHidden:NO still shows window) [v1.5.3-32]"),

    # ── v1.5.3-33 PATCHES ─────────────────────────────────────────────────────────────────────
    #
    # ROOT CAUSE OF UIView animation recursion (498× _setupAnimationWithDuration:):
    # crash log: SpringBoard-2026-08-16-025903.ips
    #   EXC_CRASH SIGBUS, faultingThread=0
    #   0× _dispatch_call_block_and_release → dispatch loop CONFIRMED FIXED by Z1
    #   498× +[UIView _setupAnimationWithDuration:...]+512 ← NEW CRASH
    #   frame[12]=img[13]+0x115EC (our animations block sub_115B8, return after setAlpha:1.0)
    #   frame[0]: NSObject superclass crash at 498-deep stack corruption
    #
    # Mechanism:
    #   sub_F2EC stop handler at 0x11270 calls [UIView animateWithDuration:animations:^sub_115B8].
    #   _setupAnimationWithDuration:+512 invokes sub_115B8 (animations block).
    #   sub_115B8 calls [var_2F8 setAlpha:1.0]:
    #     → CALayer setOpacity: → CA::Layer::begin_change → CALayer actionForKey:
    #     → UIView actionForLayer:forKey: → UIViewAnimationState actionForLayer:+104
    #     → UIViewAnimationState animationForLayer:forKey:forView:+668
    #     → AT +668: CALayer valueForKey: → calls _setupAnimationWithDuration: AGAIN
    #     → new _setupAnimationWithDuration:+512 invokes sub_115B8 again → 498× recursion
    #
    # Root cause of recursion: Z1 NOP'd setWindowScene:, leaving UIWindow without a
    # UIWindowScene. iOS 16 UIKit animation machinery (UIViewAnimationState) cannot find
    # the scene's animation controller → falls back to calling _setupAnimationWithDuration:
    # to create a new animation context → invokes the animations block again → infinite
    # recursion until stack overflow at 498 levels.
    #
    # The SAME crash would occur in sub_11754 (dispatch_after callback) which also calls
    # [UIView animateWithDuration:animations:completion:] at 0x11974 for the fade-out.
    #
    # Fix strategy: since UIView animation cannot work on a sceneless UIWindow (Z1),
    # bypass both animations entirely. The views (var_2F8/var_3A8/var_4A0/var_510) are
    # set to alpha/opacity=0 before the animation, then animated back to 1. By also
    # NOP'ing the pre-animation setAlpha:0/setOpacity:0 calls, the views remain at their
    # UIKit default (alpha=1.0, opacity=1.0) — immediately visible, no animation needed.
    # The toast appears instantly (no fade-in/fade-out) which is acceptable for PoC.
    #
    # Verified original bytes (arm64e slice base 0x2A8000, IDA vmaddr-relative):
    #   FAT+0x2B9158: 18780694 (BL _objc_msgSend) ← [var_2F8 setAlpha:0.0]      sub_F2EC 0x11158
    #   FAT+0x2B9170: 12780694 (BL _objc_msgSend) ← [var_3A8 setOpacity:0.0]    sub_F2EC 0x11170
    #   FAT+0x2B9188: 0c780694 (BL _objc_msgSend) ← [var_4A0 setOpacity:0.0]    sub_F2EC 0x11188
    #   FAT+0x2B91A0: 06780694 (BL _objc_msgSend) ← [var_510 setOpacity:0.0]    sub_F2EC 0x111A0
    #   FAT+0x2B9270: d2770694 (BL _objc_msgSend) ← [UIView animateWithDuration:animations:]     sub_F2EC 0x11270
    #   FAT+0x2B9974: 11760694 (BL _objc_msgSend) ← [UIView animateWithDuration:animations:completion:] sub_11754 0x11974

    # PATCH A1 — NOP [var_2F8 setAlpha:0.0] at sub_F2EC 0x11158 (FAT+0x2B9158)
    # Before animation: code sets toast UIView to alpha=0. NOP keeps it at default 1.0.
    (0x2B9158, bytes.fromhex("1F2003D5"), "arm64e 0x11158 NOP [var_2F8 setAlpha:0.0]: keep default alpha=1.0, no animation needed [v1.5.3-33]"),

    # PATCH A2 — NOP [var_3A8 setOpacity:0.0] at sub_F2EC 0x11170 (FAT+0x2B9170)
    (0x2B9170, bytes.fromhex("1F2003D5"), "arm64e 0x11170 NOP [var_3A8 setOpacity:0.0]: keep default opacity=1.0 [v1.5.3-33]"),

    # PATCH A3 — NOP [var_4A0 setOpacity:0.0] at sub_F2EC 0x11188 (FAT+0x2B9188)
    (0x2B9188, bytes.fromhex("1F2003D5"), "arm64e 0x11188 NOP [var_4A0 setOpacity:0.0]: keep default opacity=1.0 [v1.5.3-33]"),

    # PATCH A4 — NOP [var_510 setOpacity:0.0] at sub_F2EC 0x111A0 (FAT+0x2B91A0)
    (0x2B91A0, bytes.fromhex("1F2003D5"), "arm64e 0x111A0 NOP [var_510 setOpacity:0.0]: keep default opacity=1.0 [v1.5.3-33]"),

    # PATCH A5 — NOP [UIView animateWithDuration:animations:^sub_115B8] at 0x11270 (FAT+0x2B9270)
    # This is the fade-in animation that triggers 498× _setupAnimationWithDuration: recursion.
    # Views already at alpha=1.0 (A1-A4 NOP'd the pre-animation setAlpha:0), so NOP is safe.
    (0x2B9270, bytes.fromhex("1F2003D5"), "arm64e 0x11270 NOP [UIView animateWithDuration:animations:]: prevent 498x _setupAnimationWithDuration: recursion (sceneless UIWindow from Z1) [v1.5.3-33]"),

    # PATCH A6 — NOP [UIView animateWithDuration:0.5 animations:sub_119F4 completion:sub_11A88]
    # at sub_11754 0x11974 (FAT+0x2B9974). This is the fade-out animation in the
    # dispatch_after callback. Same recursion crash would occur for the same reason.
    # With A6, toast stays visible (no fade-out); sub_11754 still releases captured objects
    # via _objc_storeStrong calls at 0x11978-0x119E0.
    (0x2B9974, bytes.fromhex("1F2003D5"), "arm64e 0x11974 NOP [UIView animateWithDuration:0.5 animations:completion:]: prevent fade-out animation recursion in dispatch_after callback [v1.5.3-33]"),

    # ── v1.5.3-34 PATCHES ─────────────────────────────────────────────────────────────────────
    #
    # ROOT CAUSE OF "dừng lua đang chạy là safe mode ngay lập tức" (stop Lua = safe mode):
    # crash log: SpringBoard-2026-08-16-032141.ips
    #   EXC_BAD_ACCESS SIGBUS KERN_PROTECTION_FAILURE at 0x13799948A0 (GPU Carveout — unallocated)
    #   faultingThread=14, com.apple.root.default-qos (GCD global CONCURRENT queue)
    #   Thread 2 (background-qos): 507× sub_166CB8 (traversethread) → sleeping in usleep (sub_2DF1C)
    #   Thread 14 (background-qos): 509× sub_166CB8 → crash at sub_1665B8+0xAC (LDR X8,[stale ptr])
    #
    # Root cause — concurrent lua_State access:
    #   runBytecode:scriptKey:error: (IDA 0x1E818) at 0x1ECFC calls dispatch_get_global_queue(0,0)
    #   → gets com.apple.root.default-qos (CONCURRENT global queue)
    #   → dispatch_async(concurrent_queue, sub_1FA60) at 0x1ED84
    #   → sub_1FA60 calls _ws_lua53_run_bytecode → runs Lua VM on background thread
    #
    # Race when user presses "Stop" then the script auto-restarts (or presses "Run" again):
    #   1. stopAllScripts() → dispatch_sync(qword_28AD50, clear_slot) clears the running slot
    #      → _ws_lua53_stop() writes byte_28B6F0=1 (stop flag, non-blocking, does NOT wait)
    #   2. Thread 2 is still alive inside usleep (hasn't checked byte_28B6F0 yet)
    #   3. runBytecode called again → slot check passes (slot was cleared in step 1)
    #      → dispatch_async(CONCURRENT_QUEUE, lua_block) → Thread 14 starts on SAME lua_State
    #   4. Thread 14 runs luaD_growstack (inside sub_166B78) → reallocates L->stack
    #      → old L->stack pointer becomes dangling (freed by realloc)
    #   5. Thread 2 wakes from usleep, calls sub_1665B8 → reads L->stack → stale ptr = GPU Carveout
    #      → EXC_BAD_ACCESS KERN_PROTECTION_FAILURE at 0x13799948A0
    #
    # Fix: replace dispatch_get_global_queue(0,0) with qword_28AD50 ("com.webstream.lua.lock"
    # serial queue, created at 0x17590). dispatch_async on a SERIAL queue = only one Lua
    # execution at a time → no concurrent lua_State access → no stale L->stack pointer.
    #
    # Patch sites in runBytecode (IDA vmaddr, arm64e slice, FAT = vmaddr + 0x2A8000):
    #   0x1ECF4 (FAT+0x2C4CF4): MOV X1,#0     → ADRP X0, #620 (page 0x28A000 of qword_28AD50)
    #   0x1ECF8 (FAT+0x2C4CF8): MOV X0,X1     → ADD X0, X0, #0xD50  (qword_28AD50 = page+0xD50)
    #   0x1ECFC (FAT+0x2C4CFC): BL _dispatch_get_global_queue → LDR X0, [X0] (load queue ptr)
    #   0x1ED04 (FAT+0x2C4D04): BL _objc_retainAutoreleasedReturnValue → BL _objc_retain
    #     (retain serial queue to balance _objc_release at 0x1ED8C which releases var_2E0)
    #
    # Verified original bytes (IDA):
    #   0x1ECF4: d2800001 → 01 00 80 d2  MOV X1,#0 flags=0 (dispatch_get_global_queue arg)
    #   0x1ECF8: aa0103e0 → e0 03 01 aa  MOV X0,X1 identifier=0 (default-qos)
    #   0x1ECFC: 94063f53 → 53 3f 06 94  BL _dispatch_get_global_queue
    #   0x1ED04: 94064145 → 45 41 06 94  BL _objc_retainAutoreleasedReturnValue
    #
    # ADRP X0,#620 encoding: imm21=620, immlo=0, immhi=155 → 0x90001360 → 60 13 00 90
    # ADD X0,X0,#0xD50 encoding: 0x91354000 → 00 40 35 91
    # LDR X0,[X0] encoding: 0xF9400000 → 00 00 40 f9
    # BL _objc_retain from 0x1ED04: delta=+0x1904E4, imm26=0x64139 → 0x94064139 → 39 41 06 94

    # PATCH B1 — ADRP X0, page(qword_28AD50) at 0x1ECF4 [replace MOV X1, #0 (flags for dispatch_get_global_queue)]
    (0x2C4CF4, bytes.fromhex("60130090"), "arm64e 0x1ECF4 ADRP X0,page(qword_28AD50)=0x28A000: use serial lua.lock queue in runBytecode [v1.5.3-34]"),

    # PATCH B2 — ADD X0, X0, #0xD50 at 0x1ECF8 [replace MOV X0, X1 (identifier=0 for global queue)]
    (0x2C4CF8, bytes.fromhex("00403591"), "arm64e 0x1ECF8 ADD X0,X0,#0xD50: complete qword_28AD50=page+0xD50 address [v1.5.3-34]"),

    # PATCH B3 — LDR X0, [X0] at 0x1ECFC [replace BL _dispatch_get_global_queue]
    # X0 now points to qword_28AD50; LDR dereferences to get the actual serial queue object.
    (0x2C4CFC, bytes.fromhex("000040f9"), "arm64e 0x1ECFC LDR X0,[X0]: load serial queue from qword_28AD50 ptr [v1.5.3-34]"),

    # PATCH B4 — BL _objc_retain at 0x1ED04 [replace BL _objc_retainAutoreleasedReturnValue]
    # Must retain: code releases var_2E0 (the saved queue) at 0x1ED8C via _objc_release.
    # Without retain, qword_28AD50 would be over-released and could be prematurely freed.
    (0x2C4D04, bytes.fromhex("39410694"), "arm64e 0x1ED04 BL _objc_retain: retain serial queue to balance _objc_release at 0x1ED8C [v1.5.3-34]"),

    # ── v1.5.3-35 PATCHES ─────────────────────────────────────────────────────────────────────
    #
    # CRASH: SpringBoard-2026-08-16-131841.ips (v1.5.3-34)
    #   EXC_BAD_ACCESS SIGBUS at 0xe4fb362a0 (commpage reserved — unallocated)
    #   faultingThread=3 (UIKit eventfetch, mach_msg — consequence of memory corruption)
    #   Thread[0] background-qos: 507× _dispatch_call_block_and_release → tweak 0x51F54 → usleep
    #   Thread[7] default-qos:    usleep at tweak 0x2E3F0 → 507× 0x166CB8 (sub_166B78 BLRAAZ)
    #
    # ── BUG 1: unthrottled dispatch accumulation (Thread[0]) ──────────────────────────────────
    #
    # IDA workflow analysis (agent ida:dispatch-loop-0x51F54 + ida:all-dispatch-async):
    #
    # sub_51DDC (0x51DDC): "duetexpertd killer" — 3-iteration retry loop:
    #   each iteration: sysctl(KERN_PROC_ALL) → enumerate processes → strncmp 'duetexpertd'
    #   → kill(pid, SIGKILL=9) → usleep(0xF4240 = 1,000,000µs = 1s) → repeat
    #   No dispatch_async inside sub_51DDC itself.
    #
    # sub_51988 (0x51988): the dispatcher for sub_51DDC:
    #   0x519A0: BL _dispatch_get_global_queue(-32768, 0) → background-qos concurrent queue
    #   0x519B8: BL _dispatch_async(queue, &stru_221968) ← THE BUG: no rate-limit, no throttle
    #   stru_221968.invoke = sub_51DDC (confirmed via get_int at 0x221978)
    #   sub_51988 is called from:
    #     sub_2D07C (Lua 'appRun'/'apprun'/'appActivate') at 0x2D114
    #     sub_2D6A8 (Lua 'appKill'/'appkill')             at 0x2D720
    #
    # Compare: sub_519D0 (companion dispatcher for stru_221988/sub_51F90, OTA daemon killer)
    #   HAS a 30s rate-limiter via qword_28AF28 at 0x51A4C-0x51A64.
    #   sub_51988 has NO equivalent guard.
    #
    # Result: Lua script calling appRun/appKill in a loop accumulates sub_51DDC blocks on
    # background-qos concurrent pool faster than they drain (each invocation takes ~3s).
    # 507 blocks observed → 507x _dispatch_call_block_and_release frames.
    #
    # Fix options:
    #   Option A (D1): NOP the dispatch_async call inside sub_51988 at 0x519B8.
    #     → sub_51988 no longer dispatches sub_51DDC to any queue, ever.
    #     → COMPLETE fix: eliminates the entire accumulation path.
    #   Option B (D2+D3): NOP the BL sub_51988 calls from appRun/appKill.
    #     → sub_51988 is never called from Lua script context.
    #     → Defense in depth, complements D1.
    #
    # All original bytes verified by IDA patch-validation agent:
    #   0x519B8: 14 74 05 94  BL _dispatch_async (delta=_dispatch_async_stub - 0x519B8)
    #   0x2D114: 1D 92 00 94  BL sub_51988 (delta=(0x51988-0x2D114)/4 = 0x921D)
    #   0x2D720: 9A 90 00 94  BL sub_51988 (delta=(0x51988-0x2D720)/4 = 0x909A)
    #
    # PATCH D1 — NOP BL _dispatch_async at 0x519B8 in sub_51988
    (0x2F99B8, bytes.fromhex("1F2003D5"), "arm64e 0x519B8 NOP BL _dispatch_async: prevent sub_51DDC (duetexpertd 3x kill+usleep loop) from accumulating on background-qos concurrent pool with no rate-limit — eliminates 507x _dispatch_call_block_and_release on Thread[0] [v1.5.3-35]"),

    # PATCH D2 — NOP BL sub_51988 at 0x2D114 in sub_2D07C (Lua appRun/apprun/appActivate)
    (0x2D5114, bytes.fromhex("1F2003D5"), "arm64e 0x2D114 NOP BL sub_51988 in sub_2D07C (Lua appRun/apprun/appActivate): defense-in-depth, prevents dispatch accumulation from appRun path [v1.5.3-35]"),

    # PATCH D3 — NOP BL sub_51988 at 0x2D720 in sub_2D6A8 (Lua appKill/appkill)
    (0x2D5720, bytes.fromhex("1F2003D5"), "arm64e 0x2D720 NOP BL sub_51988 in sub_2D6A8 (Lua appKill/appkill): defense-in-depth, prevents dispatch accumulation from appKill path [v1.5.3-35]"),

    # ── BUG 2: GC traversethread BLRAAZ recursion (Thread[7]) — PARTIAL FIX ──────────────────
    #
    # IDA workflow analysis (agent ida:traversethread-blraaz):
    #
    # sub_166B78 (vmaddr 0x166B78) = Lua C-function dispatcher (mislabeled "traversethread").
    # Structure (IDA confirmed):
    #   0x166BCC: CBZ X8 → skip stack-grow if used_slots > 20
    #   0x166BF4: B.LE  → skip luaC_step if GCdebt <= 0
    #   0x166BFC: BL _luaC_step  ← inline GC step (only when GCdebt > 0) — C1 TARGET
    #   0x166C0C: BL _luaD_growstack
    #   0x166C48: BL sub_1670B4  (CallInfo setup)
    #   0x166C74: CBZ → skip luaD_hook if L->C0h flag clear
    #   0x166CA8: BL _luaD_hook
    #   0x166CB4: BLRAAZ X8  ← THE RECURSION POINT: calls C-function via PAC pointer
    #                           return address 0x166CB8 appears 507× in Thread[7] crash
    #
    # Recursion chain (confirmed by IDA):
    #   sub_166B78 → BLRAAZ → C-closure (sub_2DF1C = Lua sleep()) → dispatches/calls lua_call
    #   → luaV_execute → OP_CALL → _luaD_pretailcall/_luaD_precall → sub_166B78 → BLRAAZ → ...
    #
    # Why W1-W4 (v1.5.3-29) failed: 0x166884 = _luaD_pretailcall (CALL opcode handler for C closures):
    #   opcode 6  → BL sub_166B78 at 0x166900 with X3=closure+0x18 (Lua function slot)
    #   opcode 22 → BL sub_166B78 at 0x166920 with X3=closure ptr (direct)
    #   0x166E84 (_luaD_precall) mirrors: BL sub_166B78 at 0x166EF8, 0x166F1C
    #   NOP'ing these 4 BLs disables ALL Lua C function call dispatch → script crashes immediately.
    #
    # Why BLRAAZ at 0x166CB4 cannot be NOP'd: BLRAAZ IS the C-closure execution — NOP'ing it
    # silences every C function call in the Lua VM (sleep, kill, findImage, etc.).
    #
    # PARTIAL FIX — C1: NOP the inline luaC_step call at 0x166BFC.
    #   luaC_step is the GC trigger inside sub_166B78's stack-grow preamble.
    #   Only reached when: used_slots <= 20 AND GCdebt > 0.
    #   NOP'ing it prevents sub_166B78 from triggering a GC cycle during its own setup,
    #   reducing recursive pressure (GC would otherwise try to mark live C closures,
    #   potentially re-entering sub_166B78 via another path).
    #   The 507× crash return addr is 0x166CB8 (after BLRAAZ at 0x166CB4), NOT 0x166C00
    #   (after luaC_step at 0x166BFC), confirming C1 is partial — primary recursion
    #   continues via C-closure → lua_call re-entry path.
    #   PENDING: deeper investigation of sub_2DF1C dispatch_async at 0x2E230 needed
    #   to understand the full BLRAAZ recursion chain and design a complete fix.
    #
    # Original bytes at 0x166BFC: C9 0E 00 94  BL _luaC_step (verified by IDA)
    #
    # PATCH C1 — NOP BL _luaC_step at 0x166BFC in sub_166B78 (luaD_call preamble)
    (0x40EBFC, bytes.fromhex("1F2003D5"), "arm64e 0x166BFC NOP BL _luaC_step: partial fix — prevents sub_166B78 from triggering GC cycle during C-function dispatch setup (only when GCdebt>0 AND used_slots<=20); primary BLRAAZ recursion at 0x166CB4 needs further investigation [v1.5.3-35]"),

    # ── v1.5.3-37 / v1.5.3-38 PATCHES ──────────────────────────────────────────────────────────
    #
    # REVERT F1+F2 (v1.5.3-36 regression): v1.5.3-36's trampoline was built on a false
    # premise — "luaD_correctstack confirmed absent". It is NOT absent. luaD_reallocstack
    # (0x1659FC) implements the equivalent via:
    #   sub_165B28 (0x165B28): converts L->top, L+0x40, ci->func, ci->top, upval->v to
    #                           relative offsets (subtract L->stack) BEFORE luaM_realloc.
    #   sub_165C0C (0x165C0C): restores all to absolute (add new L->stack) AFTER realloc.
    # sub_165C0C walks the full ci chain and does `*j += result[6]` (ci->func += L->stack)
    # for EVERY CallInfo, including v6->func. This is the correctstack the code was missing.
    #
    # The F1 trampoline detected stack move (delta = new_stack - old_stack) and added delta
    # to v6->func — but sub_165C0C already added delta to v6->func. Double application:
    # v6->func = (original + delta) + delta = original + 2×delta = garbage address.
    # luaD_poscall wrote results to the wrong stack slot → TValue corrupted (gc=NULL but
    # type byte had GC bit 0x40 set) → GC traversethread (sub_16C408+0x9C) dereferenced
    # NULL+9=0x9 → KERN_INVALID_ADDRESS crash (v1.5.3-36 regression confirmed from
    # SpringBoard-2026-08-16-173613.ips: EXC_BAD_ACCESS at 0x0000000000000009, Thread 25).
    #

    # PATCH E1: sub_167504 nCcalls soft threshold 200 → 50 (CMP W8,#0xC8 → CMP W8,#0x32)
    # Encoding: CMP Wn,#imm12 = SUBS WZR,Wn,#imm = 0x7100001F | (imm<<10) | (Rn<<5) | 31
    # #0x32<<10 = 0xC800; Rn=W8=8: 0x7100001F | 0xC800 | 0x100 = 0x7100C91F → 1F C9 00 71
    (0x40F504, bytes.fromhex("1FC90071"), "arm64e 0x167504 CMP W8,#0x32: nCcalls sub_1674C4 soft threshold 200→50 (secondary mitigation for C-call depth) [v1.5.3-37]"),

    # PATCH E2: luaE_checkcstack soft threshold 200 → 50 (vmaddr 0x17CC04, FAT+0x424C04)
    (0x424C04, bytes.fromhex("1FC90071"), "arm64e 0x17CC04 CMP W8,#0x32: luaE_checkcstack soft limit 200→50 [v1.5.3-37]"),

    # PATCH E3: luaE_checkcstack fatal threshold 220 → 70 (vmaddr 0x17CC28, FAT+0x424C28)
    # CMP W8,#0x46: #0x46<<10=0x11800; 0x7100001F|0x11800|0x100 = 0x7101191F → 1F 19 01 71
    (0x424C28, bytes.fromhex("1F190171"), "arm64e 0x17CC28 CMP W8,#0x46: luaE_checkcstack fatal limit 220→70 [v1.5.3-37]"),

    # PATCH E2b: luaE_checkcstack soft branch B.NE → B.LO (vmaddr 0x17CC08, FAT+0x424C08)
    # WHY: E2 changed CMP threshold from 200 to 50. But the branch at 0x17CC08 is B.NE
    # (fires soft error only when nCcalls == 50, exact match). After pcall catches the error
    # and longjmp unwinds, sub_1674C4's decrement at 0x1675E0 never runs → nCcalls stays
    # elevated. Confirmed: luaD_pcall (0x167D14) does NOT restore L->nCcalls (saves only
    # L->ci, L->allowhooks, L->errfunc). So nCcalls stays at 50, next call increments to 51,
    # B.NE check: 51 != 50 → branch skips error → recursion continues to 509 levels → OOM.
    #
    # FIX: Change B.NE to B.LO (branch if Lower, unsigned <). New logic:
    #   - B.LO taken if nCcalls < 50  → skip error (nCcalls below threshold)
    #   - B.LO NOT taken if nCcalls >= 50 → fall through to luaG_runerror (soft error)
    # Now EVERY call at nCcalls >= 50 throws immediately via longjmp → C thread stack
    # stays shallow after each throw/catch cycle → OOM (pmap_enter resource shortage
    # from 509 deep C frames) is prevented even though nCcalls grows monotonically.
    #
    # Encoding: B.cond = 0x54 | (imm19<<5) | cond
    #   imm19 = (0x17CC1C - 0x17CC08) / 4 = 5; cond(NE)=1 → 0x540000A1 → A1 00 00 54 (old)
    #   cond(LO/CC)=3 → 0x540000A3 → A3 00 00 54 (new)
    # Verified old bytes at FAT+0x424C04..0x424C0B: 1f 21 03 71 A1 00 00 54 ✓
    (0x424C08, bytes.fromhex("A3000054"), "arm64e 0x17CC08 B.LO: luaE_checkcstack soft limit B.NE→B.LO (==50 → >=50); prevents 509-deep C stack OOM (luaD_pcall confirmed no nCcalls restore) [v1.5.3-38]"),

]


# ── WSDaemon patches ──────────────────────────────────────────────────────────
#
# WSDaemon is a FAT binary (arm64 @ FAT+0x4000 + arm64e @ FAT+0x1C000) that runs
# as a LaunchDaemon and has its OWN safemode-recovery reboot logic:
#
#   [WSDaemon] watchdog safemode detected, recovering...
#   → posix_spawn("/var/jb/usr/bin/launchctl", ["reboot", "userspace"])  ← REBOOT TRIGGER
#   [WSDaemon] watchdog recovery done
#
# When the tweak crashes SpringBoard, iOS watchdog puts the system in safemode.
# WSDaemon detects this and triggers a userspace reboot as "recovery".
# After the reboot SpringBoard is loaded again, the tweak crashes again → watchdog safemode
# → WSDaemon reboots again → permanent bootloop. This is the ACTUAL root cause that
# persisted through v1.5.3-17 (which only patched reboot calls inside rh_main.dylib).
#
# arm64e slice (iPhone XS A12 uses this):
#   Function at FAT+0x20D20 (VA=0x100004D20): PACIBSP then STP X28,X27 frame,
#   references "reboot_userspace" cstring, calls posix_spawn reboot.
#   Same fc6fbea9 STP pattern as rh_main.dylib auto-reboot timer.
#   Patch: FAT+0x20D24 = RETAB (FF 0F 5F D6) — early-exit after PACIBSP.
#
# arm64 slice (included for completeness / fallback):
#   Function at FAT+0x8F54 (VA=0x100004F54): no PACIBSP, starts with BL immediately.
#   References "reboot_userspace" cstring, same logic as arm64e counterpart.
#   Patch: FAT+0x8F54 = NOP;RET (1F 20 03 D5  C0 03 5F D6) — 8 bytes, overwrite start.

WSD_PATCHES = [
    # (fat_offset, patch_bytes, description)
    #
    # arm64e slice: FAT+0x1C000 base, function at FAT+0x20D20
    #   PACIBSP at +0 (FAT+0x20D20), STP X28,X27 at +4 (FAT+0x20D24)
    #   Patch +4 with RETAB: signs LR on entry (PACIBSP), immediately returns (RETAB).
    #   PACIBSP+RETAB pair is balanced — SP unchanged, authentication succeeds.
    (0x20D24, bytes.fromhex("FF0F5FD6"),         "WSDaemon arm64e watchdog-recovery reboot: RETAB at fn+4 (orig=fc6fbea9)"),
    #
    # arm64 slice: FAT+0x4000 base, _wsd_safemode_recovery_thread at FAT+0x8B18
    #   Confirmed from crash log: imageOffset=0x4E70, symbolLocation=856 (=0x358)
    #   → fn start = 0x4E70 - 0x358 = 0x4B18 → FAT = 0x4000+0x4B18 = 0x8B18
    #   PREVIOUS WRONG PATCH was at FAT+0x8F54 (+0x43C into fn, a BL instr, never reached
    #   because the crash at +0x358 happens first due to PAC-corrupted LR from arm64e hooks).
    #   Function has NO PACIBSP (plain arm64). First 8 bytes: STP X28,X27 + STP X29,X30.
    #   Caller (_pthread_start, arm64e) uses BLR (not BLRAB) for arm64 thread functions,
    #   so LR is NOT PAC-signed on entry → NOP;RET at fn start returns safely to _pthread_start.
    (0x8B18,  bytes.fromhex("1F2003D5C0035FD6"), "WSDaemon arm64   _wsd_safemode_recovery_thread: NOP;RET at fn+0 (orig=fc6fbea9 fd7b01a9) [v1.5.3-20 FIXED]"),
]


# ── Ad-hoc Code Signature Regeneration ───────────────────────────────────────
#
# Root cause of v1.5.3-20 bootloop:
#   Our byte patches invalidate the SHA-256 page hashes stored in the CodeDirectory
#   of each Mach-O slice.  iOS enforces page-level code signing via vm_fault: when a
#   modified __TEXT page is first executed (or accessed by a jailbreak injector),
#   the kernel hashes the page and compares against the CodeDirectory.  Mismatch →
#   SIGKILL with exception code 0x32 "Invalid Page" (CODESIGNING namespace).
#
#   SpringBoard crash log showed:
#     "signal":"SIGKILL - CODESIGNING"
#     "termination":{"namespace":"CODESIGNING","indicator":"Invalid Page"}
#   at address 0x1008074c8 inside __TEXT of 0a04abcf5ee4aiam7b7c131c.dylib.
#   The modified page (arm64e local 0x7000-0x7FFF, containing our NOP patches at
#   0x7914 and 0x7AB0) failed hash verification → SpringBoard killed immediately.
#
# Fix: after all byte patches, regenerate an ad-hoc CodeDirectory (CSMAGIC_CODEDIRECTORY)
#   with fresh SHA-256 hashes for every 4 KB code page.  The jailbreak's amfid bypass
#   allows ad-hoc signed dylibs/binaries to run.  No CMS blob needed.
#
# Reference structures (Apple cs_blobs.h):
#   SuperBlob  0xFADE0CC0: magic(I) length(I) count(I) [type(I) offset(I)]...
#   CodeDirectory 0xFADE0C02 v0x20400: 88-byte fixed header, then ident, then hashes.

def _build_code_directory(slice_bytes, code_limit, identifier):
    """Build CSMAGIC_CODEDIRECTORY with SHA-256 hashes for all 4 KB pages."""
    PAGE  = 4096   # iOS always uses 4 KB code-signing pages, even on 16 KB page devices
    HS    = 32     # SHA-256 digest size
    ident = identifier if identifier.endswith(b'\x00') else identifier + b'\x00'
    npages = math.ceil(code_limit / PAGE)

    # v0x20400 fixed header: 9×I + 4×B + 4×I + 4×Q = 88 bytes
    CD_HDR    = 88
    ident_off = CD_HDR
    hash_off  = ident_off + len(ident)   # 0 special slots: hashes start right after ident
    cd_len    = hash_off + npages * HS

    hdr = struct.pack(">IIIIIIIIIBBBBIIIIQQQQ",
        0xFADE0C02,   # magic
        cd_len,       # length
        0x20400,      # version
        0x2,          # flags: CS_ADHOC
        hash_off,     # hashOffset (from CD start to code-slot[0])
        ident_off,    # identOffset (from CD start)
        0,            # nSpecialSlots
        npages,       # nCodeSlots
        code_limit,   # codeLimit (uint32, bytes covered before the sig)
        HS, 2, 0, 12, # hashSize=32, hashType=SHA256, platform=0, pageSize=log2(4096)
        0, 0, 0, 0,   # spare2, scatterOffset, teamOffset, spare3
        0,            # codeLimit64
        0, 0, 0,      # execSegBase, execSegLimit, execSegFlags
    )

    hashes = bytearray()
    for i in range(npages):
        pg_s = i * PAGE
        pg_e = min(pg_s + PAGE, code_limit)
        page = bytes(slice_bytes[pg_s:pg_e]).ljust(PAGE, b'\x00')
        hashes += hashlib.sha256(page).digest()

    cd = hdr + ident + bytes(hashes)
    assert len(cd) == cd_len, f"CD size mismatch: {len(cd)} vs {cd_len}"
    return cd


def _update_page_hashes(data, fat_slice_off, label="slice"):
    """Update page hash values in the existing CodeDirectory — surgical in-place fix.

    After binary patching some __TEXT pages, only the page hash VALUES in the
    CodeDirectory need to change.  Everything else — SuperBlob structure, all other
    blobs (entitlements, requirements, CMS), CodeDirectory version/flags/identOffset/
    nSpecialSlots/special-slot hashes, etc. — is preserved byte-identical.

    Rationale: _resign_slice (prior approach) replaced the whole SuperBlob with a
    minimal one containing only a CodeDirectory.  This dropped the entitlements blob
    that roothidehooks.dylib reads at startup to determine injection strategy.  With
    the entitlements blob missing, roothidehooks crashed inside dyld's own r-- mapped
    region within 14 ms of WSDaemon launch — before any frames were visible.
    Preserving the original SuperBlob structure prevents that crash entirely.
    """
    s = fat_slice_off

    magic = struct.unpack_from("<I", data, s)[0]
    if magic not in (0xFEEDFACF, 0xFEEDFACE):
        print(f"  [resign:{label}] No Mach-O at FAT+0x{s:X} — skip"); return False

    ncmds = struct.unpack_from("<I", data, s + 16)[0]
    lc    = s + (32 if magic == 0xFEEDFACF else 28)

    cs_data_off = None
    for _ in range(ncmds):
        cmd = struct.unpack_from("<I", data, lc)[0]
        csz = struct.unpack_from("<I", data, lc + 4)[0]
        if cmd == 0x1D:   # LC_CODE_SIGNATURE
            cs_data_off = struct.unpack_from("<I", data, lc + 8)[0]
            break
        lc += csz
    if cs_data_off is None:
        print(f"  [resign:{label}] No LC_CODE_SIGNATURE — skip"); return False

    sb_abs = s + cs_data_off
    if struct.unpack_from(">I", data, sb_abs)[0] != 0xFADE0CC0:
        print(f"  [resign:{label}] No SuperBlob — skip"); return False

    # Locate the primary CodeDirectory (CSSLOT_CODEDIRECTORY = type 0)
    count  = struct.unpack_from(">I", data, sb_abs + 8)[0]
    cd_abs = None
    for i in range(count):
        btype = struct.unpack_from(">I", data, sb_abs + 12 + i * 8)[0]
        boff  = struct.unpack_from(">I", data, sb_abs + 16 + i * 8)[0]
        if btype == 0:
            cd_abs = sb_abs + boff
            break
    if cd_abs is None or struct.unpack_from(">I", data, cd_abs)[0] != 0xFADE0C02:
        print(f"  [resign:{label}] No CodeDirectory in SuperBlob — skip"); return False

    # Read CodeDirectory fields (big-endian, fixed layout up to v0x20000)
    hash_off  = struct.unpack_from(">I", data, cd_abs + 16)[0]  # hashOffset
    n_special = struct.unpack_from(">I", data, cd_abs + 24)[0]  # nSpecialSlots
    n_code    = struct.unpack_from(">I", data, cd_abs + 28)[0]  # nCodeSlots
    cl32      = struct.unpack_from(">I", data, cd_abs + 32)[0]  # codeLimit
    hs        = struct.unpack_from("B",  data, cd_abs + 36)[0]  # hashSize
    ht        = struct.unpack_from("B",  data, cd_abs + 37)[0]  # hashType (2=SHA256)
    ps        = struct.unpack_from("B",  data, cd_abs + 39)[0]  # pageSize (log2)
    PAGE      = 1 << ps

    if ht != 2 or hs != 32:
        print(f"  [resign:{label}] Unsupported hashType={ht}/hashSize={hs} — skip"); return False

    print(f"  [resign:{label}] FAT+0x{s:X}  codeLimit=0x{cl32:X}  "
          f"pages={n_code}  PAGE={PAGE}  special={n_special}")

    # code slot [i] is at:  cd_abs + hash_off + i * hs
    # special slots live at NEGATIVE indices before code slot 0 — untouched here
    slice_bytes = bytes(data[s : s + cl32])
    updated = 0
    for i in range(n_code):
        pg_s = i * PAGE
        pg_e = min(pg_s + PAGE, cl32)
        page = bytes(slice_bytes[pg_s:pg_e]).ljust(PAGE, b'\x00')
        new_hash = hashlib.sha256(page).digest()
        ha = cd_abs + hash_off + i * hs
        if bytes(data[ha : ha + hs]) != new_hash:
            data[ha : ha + hs] = new_hash
            updated += 1

    print(f"  [resign:{label}] OK — {updated}/{n_code} page hashes updated "
          f"(special={n_special} preserved, SuperBlob structure unchanged)")
    return True


def patch_wsdaemon(raw):
    """Patch WSDaemon binary in-place: disable safemode watchdog recovery reboot."""
    data = bytearray(raw)
    print(f"  WSDaemon: {len(data):,} B  SHA256={hashlib.sha256(raw).hexdigest()[:16]}...")
    for offset, patch, label in WSD_PATCHES:
        n = len(patch)
        before = bytes(data[offset:offset+n])
        data[offset:offset+n] = patch
        print(f"  {label}")
        print(f"    WSD_FAT+0x{offset:06X}  {before.hex(' ')} -> {patch.hex(' ')}")
    # WSDaemon: CS_ENFORCEMENT (0x1000) is NOT set in codeSigningFlags (0x22000105).
    # Without CS_ENFORCEMENT the kernel does NOT validate page hashes on execution,
    # so we must NOT call _update_page_hashes here — doing so triggers a CODESIGNING
    # kernel path that wasn't previously active and causes SIGKILL at __LINKEDIT during
    # dyld fixup (confirmed in v1.5.3-22 crash: codeSigningFlags=0x23000105=CS_KILLED set).
    patched = bytes(data)
    print(f"  Patched SHA256={hashlib.sha256(patched).hexdigest()[:16]}...")
    return patched


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

    # Update page hashes in the existing CodeDirectory (surgical in-place, preserves SuperBlob).
    print()
    _update_page_hashes(data, 0x4000,          "arm64-dylib")
    _update_page_hashes(data, ARM64E_SLICE_OFF, "arm64e-dylib")

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

    # v1.5.3-20: plist filter restored to original (SpringBoard injection re-enabled).
    # Diagnostic v1.5.3-19-debug confirmed the crash source. WSDaemon arm64 patch
    # corrected to FAT+0x8B18 (true function start of _wsd_safemode_recovery_thread).
    print("\n=== Plist filter: keeping original (SpringBoard injection enabled) ===")

    print("\n=== Patching dylib(s) ===")
    d_overrides = {}
    for k in dylib_keys:
        print(f"\n--- {k} ---")
        d_overrides[k] = patch_dylib(d_fd[k])

    # ── Patch WSDaemon ────────────────────────────────────────────────────────
    wsd_key = "./usr/bin/WSDaemon"
    if wsd_key in d_fd and d_fd[wsd_key]:
        print(f"\n=== Patching WSDaemon ===")
        d_overrides[wsd_key] = patch_wsdaemon(d_fd[wsd_key])
    else:
        print(f"\nWARNING: {wsd_key} not found in data tar — skipping WSDaemon patch")

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
                lines.append("Version: 1.5.3-40+poc")
            elif line.startswith("Depends:"):
                val = line.rstrip()
                if "oldabi" not in val:
                    val += ", oldabi"
                lines.append(val)
            else:
                lines.append(line)
        c_over[ctrl_key] = ("\n".join(lines) + "\n").encode()
        print("Updated control: Version 1.5.3-40+poc, oldabi in Depends, postinst original")
    # postinst: keep original; signing is done in-patcher by _resign_slice (Python SHA-256)

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
    print("arm64e: system(reboot) wrapper 0xB45D4 RETAB'd [v1.5.3-16].")
    print("arm64e: system(killall SpringBoard) wrapper 0xB4604 RETAB'd [v1.5.3-16].")
    print("arm64e: IOHIDEventSystemClientDispatchEvent(NULL) in 0x4C33C NOP'd at 0x4C714 [v1.5.3-16].")
    print("arm64e: generic system() executor 0x13DF7C RETAB'd [v1.5.3-16].")
    print("arm64e: generic system() executor 0x176A64 RETAB'd [v1.5.3-16].")
    print("arm64e: 9x posix_spawn(launchctl reboot userspace) RETAB'd [v1.5.3-17].")
    print("WSDaemon arm64e: watchdog-safemode reboot RETAB'd [v1.5.3-18 NEW].")
    print("WSDaemon arm64:  watchdog-safemode reboot NOP+RET'd [v1.5.3-18 NEW].")
    print("arm64:  all 5 license functions bypassed.")
    print("arm64e: PATCH V1+V2 (v1.5.3-28): two NOPs inside 0x1665B8 at 0x1666DC/0x1666E0.")
    print("  V1: NOP bl #0x16939c breaks 9-hop GC recursion; 0x1665B8 result-adjuster still runs.")
    print("  V2: NOP stur x0,[x29,#-0x10] preserves func_obj=CI->func for write-barrier.")
    print("arm64e: PATCH Z1 (v1.5.3-32): NOP setWindowScene: at 0xFB24 breaks FBScene dispatch loop.")
    print("arm64e: PATCH A1-A6 (v1.5.3-33): fix UIView animation 498x recursion on sceneless UIWindow.")
    print("  A1-A4: NOP setAlpha:0/setOpacity:0 at 0x11158/0x11170/0x11188/0x111A0 (keep default 1.0).")
    print("  A5: NOP animateWithDuration:animations: at 0x11270 (fade-in, views already at 1.0).")
    print("  A6: NOP animateWithDuration:animations:completion: at 0x11974 in sub_11754 (fade-out).")
    print("arm64e: PATCH B1-B4 (v1.5.3-34): fix concurrent lua_State crash (stop Lua = safe mode).")
    print("  Root cause: runBytecode dispatches Lua to concurrent default-qos queue → two threads")
    print("    share same lua_State → luaD_growstack on Thread 14 frees L->stack → Thread 2 crashes.")
    print("  B1: ADRP X0,page(qword_28AD50) at 0x1ECF4 (replaces MOV X1,#0 / flags=0).")
    print("  B2: ADD X0,X0,#0xD50 at 0x1ECF8 (replaces MOV X0,X1 / identifier=0).")
    print("  B3: LDR X0,[X0] at 0x1ECFC (replaces BL _dispatch_get_global_queue).")
    print("  B4: BL _objc_retain at 0x1ED04 (replaces BL _objc_retainAutoreleasedReturnValue).")
    print("arm64e: PATCH D1-D3 (v1.5.3-35): fix sub_51DDC (duetexpertd killer) dispatch accumulation.")
    print("  Root cause: sub_51988 dispatches sub_51DDC to background-qos concurrent queue with NO")
    print("    rate-limit. Lua appRun/appKill call sub_51988 on every invocation. Each sub_51DDC")
    print("    invocation takes ~3s (3×usleep(1s)); at 500+ calls → 507x _dispatch_call_block_and_release.")
    print("  D1: NOP BL _dispatch_async at 0x519B8 in sub_51988 (eliminates dispatch entirely).")
    print("  D2: NOP BL sub_51988 at 0x2D114 in sub_2D07C (appRun/apprun/appActivate, defense-in-depth).")
    print("  D3: NOP BL sub_51988 at 0x2D720 in sub_2D6A8 (appKill/appkill, defense-in-depth).")
    print("arm64e: PATCH C1 (v1.5.3-35): partial fix for sub_166B78 BLRAAZ GC recursion.")
    print("  C1: NOP BL _luaC_step at 0x166BFC (inline GC step in luaD_call preamble).")
    print("  Reduces GC pressure. Primary recursion cause still under investigation.")
    print("  Result: dispatch_async uses serial 'com.webstream.lua.lock' queue →")
    print("    only ONE Lua VM execution at a time → no concurrent lua_State access.")
    print("arm64e: PATCH F1+F2 REVERTED (v1.5.3-37): these patches caused DOUBLE-DELTA corruption.")
    print("  luaD_reallocstack (0x1659FC) ALREADY corrects all StkId via sub_165B28+sub_165C0C.")
    print("  sub_165C0C walks ci chain and adds new L->stack to every ci->func (incl. v6->func).")
    print("  F1 trampoline was adding delta AGAIN → v6->func = correct + delta = garbage →")
    print("  luaD_poscall wrote to wrong slot → TValue(gc=NULL, tt|=0x40) → GC crash at 0x9.")
    print("  Confirmed: SpringBoard-2026-08-16-173613.ips EXC_BAD_ACCESS 0x9, Thread 25.")
    print("arm64e: PATCH E1-E3 (v1.5.3-37): tighten nCcalls / luaE_checkcstack thresholds.")
    print("arm64e: PATCH E2b (v1.5.3-38): fix luaE_checkcstack B.NE→B.LO at 0x17CC08.")
    print("  luaD_pcall (0x167D14) confirmed: does NOT restore L->nCcalls after longjmp.")
    print("  Old B.NE: soft error fires only at nCcalls==50 (exact match). After pcall catches,")
    print("  nCcalls stays elevated (decrement at sub_1674C4+0x1675E0 never runs). Level 51+")
    print("  bypass check (51!=50). Recursion continues to 509 levels → OOM.")
    print("  New B.LO: branch skips error only when nCcalls<50. For nCcalls>=50, falls through")
    print("  to luaG_runerror every time → immediate longjmp → C stack stays shallow → no OOM.")
    print("  E1: CMP W8,#0x32 at 0x167504 (sub_1674C4 soft limit: 200→50).")
    print("  E2: CMP W8,#0x32 at 0x17CC04 (luaE_checkcstack soft limit: 200→50).")
    print("  E3: CMP W8,#0x46 at 0x17CC28 (luaE_checkcstack fatal limit: 220→70).")


if __name__ == "__main__":
    main()
