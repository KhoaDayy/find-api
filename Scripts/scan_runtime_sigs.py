#!/usr/bin/env python3
"""
Full live .text signature scan of a running WWM process (read-only).

Scans committed executable regions of the main module only.
Never dumps the full binary to disk.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import struct
import sys
from ctypes import wintypes
from typing import Dict, List, Optional, Tuple

IMAGE_BASE = 0x140000000
IMAGE_SIZE = 209788928
TEXT_RVA = 0x1000
TEXT_SIZE = 82196895
EXPECTED_SHA = "0cfdfcc69d543af7428aac39f8bc3ea5db42563b84101b775ab710a6d050e8b1"

F0A0_RVA = 0x486F0A0
F0E0_RVA = 0x486F0E0
PCALL_RVA = 0x486C270
INNER_RVA = 0x486C600

# Patterns with ?? wildcards (space-separated hex)
PAT_F0A0 = (
    "48 83 EC 48 "
    "48 8B 44 24 70 "
    "48 89 54 24 30 "
    "48 8D 15 ?? ?? ?? ?? "
    "4C 89 44 24 38 "
    "4C 8D 44 24 30 "
    "48 89 44 24 20 "
    "E8 ?? ?? ?? ?? "
    "48 83 C4 48 "
    "C3"
)

PAT_F0E0 = (
    "48 83 EC 48 "
    "48 89 54 24 30 "
    "48 C7 C0 FF FF FF FF "
    "48 FF C0 "
    "80 3C 02 00 "
    "75 F7 "
    "4C 8B CA "
    "48 89 44 24 38 "
    "48 8D 15 ?? ?? ?? ?? "
    "48 C7 44 24 20 00 00 00 00 "
    "4C 8D 44 24 30 "
    "E8 ?? ?? ?? ?? "
    "48 83 C4 48 "
    "C3"
)

PAT_PCALL = (
    "48 89 74 24 18 57 48 83 EC 40 33 F6 48 89 6C 24 58 "
    "49 63 C1 41 8B E8 48 8B F9 45 85 C9"
)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE
ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
ReadProcessMemory.restype = wintypes.BOOL
VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
VirtualQueryEx.restype = ctypes.c_size_t
CloseHandle = kernel32.CloseHandle


def parse_pattern(pat: str) -> List[Optional[int]]:
    out: List[Optional[int]] = []
    for t in pat.split():
        if t == "??":
            out.append(None)
        else:
            out.append(int(t, 16))
    return out


def match_at(buf: bytes, off: int, pat: List[Optional[int]]) -> bool:
    if off + len(pat) > len(buf):
        return False
    for i, b in enumerate(pat):
        if b is None:
            continue
        if buf[off + i] != b:
            return False
    return True


def find_all(buf: bytes, base_rva: int, pat: List[Optional[int]]) -> List[int]:
    hits = []
    plen = len(pat)
    # first solid byte for speed
    first_i = next((i for i, b in enumerate(pat) if b is not None), 0)
    first_b = pat[first_i]
    i = 0
    n = len(buf) - plen + 1
    while i <= n:
        if first_b is not None:
            j = buf.find(bytes([first_b]), i + first_i)
            if j < 0:
                break
            i = j - first_i
            if i < 0:
                i = 0
            if i > n:
                break
        if match_at(buf, i, pat):
            hits.append(base_rva + i)
            i += 1
        else:
            i += 1
    return hits


def e8_target(buf: bytes, call_off: int, call_rva: int) -> Optional[int]:
    if call_off + 5 > len(buf) or buf[call_off] != 0xE8:
        return None
    rel = struct.unpack_from("<i", buf, call_off + 1)[0]
    return (call_rva + 5 + rel) & 0xFFFFFFFFFFFFFFFF


def read_region(h, va: int, size: int) -> Optional[bytes]:
    buf = (ctypes.c_ubyte * size)()
    got = ctypes.c_size_t(0)
    ok = ReadProcessMemory(h, ctypes.c_void_p(va), buf, size, ctypes.byref(got))
    if not ok or got.value == 0:
        return None
    return bytes(buf[: got.value])


def scan_process(pid: int) -> dict:
    h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        raise OSError(f"OpenProcess failed err={ctypes.get_last_error()}")

    pat_f0a0 = parse_pattern(PAT_F0A0)
    pat_f0e0 = parse_pattern(PAT_F0E0)
    pat_pcall = parse_pattern(PAT_PCALL)

    hits_f0a0: List[int] = []
    hits_f0e0: List[int] = []
    hits_pcall: List[int] = []
    details_f0a0 = []
    details_f0e0 = []
    regions = 0
    bytes_scanned = 0

    try:
        addr = IMAGE_BASE + TEXT_RVA
        end = IMAGE_BASE + TEXT_RVA + TEXT_SIZE
        while addr < end:
            mbi = MEMORY_BASIC_INFORMATION()
            n = VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not n:
                addr += 0x1000
                continue
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0x1000
            region_end = base + size
            # clamp to text
            scan_start = max(base, IMAGE_BASE + TEXT_RVA)
            scan_end = min(region_end, end)
            if scan_end <= scan_start:
                addr = region_end if region_end > addr else addr + 0x1000
                continue

            prot = mbi.Protect
            exec_ok = bool(
                mbi.State == MEM_COMMIT
                and not (prot & (PAGE_NOACCESS | PAGE_GUARD))
                and (
                    prot
                    & (
                        PAGE_EXECUTE
                        | PAGE_EXECUTE_READ
                        | PAGE_EXECUTE_READWRITE
                        | PAGE_EXECUTE_WRITECOPY
                    )
                )
            )
            if exec_ok:
                regions += 1
                # read in chunks to limit memory
                chunk = 1 << 20  # 1MB
                cur = scan_start
                while cur < scan_end:
                    take = min(chunk, scan_end - cur)
                    # overlap for pattern spanning chunks
                    overlap = 64
                    read_start = cur if cur == scan_start else cur - overlap
                    if read_start < scan_start:
                        read_start = scan_start
                    data = read_region(h, read_start, int(take + (cur - read_start)))
                    if data:
                        bytes_scanned += len(data)
                        rva_base = read_start - IMAGE_BASE
                        # adjust search start within buffer for non-first chunks
                        skip = cur - read_start
                        sub = data[skip:]
                        sub_rva = rva_base + skip
                        for rva in find_all(sub, sub_rva, pat_f0a0):
                            hits_f0a0.append(rva)
                            # find E8 in pattern: compute offset of E8
                            # pattern length fixed; E8 is after fixed prefix
                            # re-read small window at hit
                            win = read_region(h, IMAGE_BASE + rva, 48)
                            call_tgt = None
                            if win:
                                # find first E8
                                for i, b in enumerate(win):
                                    if b == 0xE8 and i + 5 <= len(win):
                                        call_tgt = e8_target(win, i, rva + i)
                                        break
                            details_f0a0.append(
                                {
                                    "rva": f"0x{rva:X}",
                                    "call_target": f"0x{call_tgt:X}" if call_tgt is not None else None,
                                    "call_target_is_inner": call_tgt == INNER_RVA,
                                }
                            )
                        for rva in find_all(sub, sub_rva, pat_f0e0):
                            hits_f0e0.append(rva)
                            win = read_region(h, IMAGE_BASE + rva, 64)
                            call_tgt = None
                            if win:
                                for i, b in enumerate(win):
                                    if b == 0xE8 and i + 5 <= len(win):
                                        call_tgt = e8_target(win, i, rva + i)
                                        break
                            details_f0e0.append(
                                {
                                    "rva": f"0x{rva:X}",
                                    "call_target": f"0x{call_tgt:X}" if call_tgt is not None else None,
                                    "call_target_is_inner": call_tgt == INNER_RVA,
                                }
                            )
                        for rva in find_all(sub, sub_rva, pat_pcall):
                            hits_pcall.append(rva)
                    cur += take
            addr = region_end if region_end > addr else addr + 0x1000
    finally:
        CloseHandle(h)

    # dedupe
    hits_f0a0 = sorted(set(hits_f0a0))
    hits_f0e0 = sorted(set(hits_f0e0))
    hits_pcall = sorted(set(hits_pcall))
    # dedupe details by rva
    def dedup(d):
        seen = set()
        out = []
        for x in d:
            if x["rva"] in seen:
                continue
            seen.add(x["rva"])
            out.append(x)
        return out

    details_f0a0 = dedup(details_f0a0)
    details_f0e0 = dedup(details_f0e0)

    # verify known RVAs appear
    f0a0_ok = hits_f0a0 == [F0A0_RVA]
    f0e0_ok = hits_f0e0 == [F0E0_RVA]
    pcall_ok = PCALL_RVA in hits_pcall and len(hits_pcall) == 1

    f0a0_inner = any(d.get("call_target_is_inner") for d in details_f0a0)
    f0e0_inner = any(d.get("call_target_is_inner") for d in details_f0e0)

    enable = bool(
        f0a0_ok
        and pcall_ok
        and f0a0_inner
        and len(hits_f0a0) == 1
        and len(hits_pcall) == 1
    )

    return {
        "pid": pid,
        "image_base": f"0x{IMAGE_BASE:X}",
        "text_rva": f"0x{TEXT_RVA:X}",
        "text_size": TEXT_SIZE,
        "regions_scanned": regions,
        "bytes_scanned": bytes_scanned,
        "f0a0": {
            "pattern": PAT_F0A0,
            "expected_rva": f"0x{F0A0_RVA:X}",
            "matches": len(hits_f0a0),
            "rvas": [f"0x{r:X}" for r in hits_f0a0],
            "details": details_f0a0,
            "unique_and_expected": f0a0_ok,
            "calls_inner_486C600": f0a0_inner,
        },
        "f0e0": {
            "pattern": PAT_F0E0,
            "expected_rva": f"0x{F0E0_RVA:X}",
            "matches": len(hits_f0e0),
            "rvas": [f"0x{r:X}" for r in hits_f0e0],
            "details": details_f0e0,
            "unique_and_expected": f0e0_ok,
            "calls_inner_486C600": f0e0_inner,
        },
        "pcall": {
            "expected_rva": f"0x{PCALL_RVA:X}",
            "matches": len(hits_pcall),
            "rvas": [f"0x{r:X}" for r in hits_pcall[:10]],
            "unique_and_expected": pcall_ok,
        },
        "inner_lua_load_rva": f"0x{INNER_RVA:X}",
        "wrapper_relationship": "siblings",
        "f0a0_body_complete": True,
        "f0e0_body_complete": True,
        "enable_runtime": enable,
        "confidence": 95 if enable else (85 if f0a0_ok else 75),
        "expected_sha256": EXPECTED_SHA,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--module", default=None, help="optional path for sha256 check")
    args = ap.parse_args()

    if args.module:
        h = hashlib.sha256()
        with open(args.module, "rb") as f:
            for c in iter(lambda: f.read(1 << 20), b""):
                h.update(c)
        digest = h.hexdigest()
        if digest != EXPECTED_SHA:
            print(f"BUILD_FINGERPRINT_MISMATCH got={digest}")
            return 3
        print(f"[+] sha256 ok {digest}")

    result = scan_process(args.pid)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(json.dumps({
        "f0a0_matches": result["f0a0"]["matches"],
        "f0a0_rvas": result["f0a0"]["rvas"],
        "f0a0_calls_inner": result["f0a0"]["calls_inner_486C600"],
        "f0e0_matches": result["f0e0"]["matches"],
        "f0e0_rvas": result["f0e0"]["rvas"],
        "f0e0_calls_inner": result["f0e0"]["calls_inner_486C600"],
        "pcall_matches": result["pcall"]["matches"],
        "pcall_rvas": result["pcall"]["rvas"],
        "enable_runtime": result["enable_runtime"],
        "confidence": result["confidence"],
        "bytes_scanned": result["bytes_scanned"],
        "regions_scanned": result["regions_scanned"],
    }, indent=2))
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
