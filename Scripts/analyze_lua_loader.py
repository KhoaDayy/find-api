#!/usr/bin/env python3
"""
Offline / process-memory analysis of WWM Lite Lua loader candidates.

The on-disk wwm.exe is packed (.text RawSize=0). Prefer:
  1) --dump  : raw image dump (VA base 0x140000000 layout) if available
  2) --pid   : read committed pages from a running wwm.exe (Admin)
  3) probe JSON hex windows as fallback for local evidence only

Never hooks. Never patches. Never commits game binary.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import struct
import sys
from ctypes import wintypes
from typing import Dict, List, Optional, Tuple

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    print("Missing capstone. pip install -r requirements-hook-analysis.txt", file=sys.stderr)
    sys.exit(2)

EXPECTED_SHA256 = "0cfdfcc69d543af7428aac39f8bc3ea5db42563b84101b775ab710a6d050e8b1"
PCALL_RVA = 0x486C270
IMAGE_BASE = 0x140000000

# Known first32 from live probe (runtime memory)
KNOWN_FIRST32 = {
    0x486F0E0: bytes.fromhex(
        "48 83 EC 48 48 89 54 24 30 48 C7 C0 FF FF FF FF "
        "48 FF C0 80 3C 02 00 75 F7 4C 8B CA 48 89 44 24"
    ),
    0x486F0A0: bytes.fromhex(
        "48 83 EC 48 48 8B 44 24 70 48 89 54 24 30 48 8D 15 "
        "EB 10 00 00 4C 89 44 24 38 4C 8D 44 24 30 48"
    ),
    0x486C270: bytes.fromhex(
        "48 89 74 24 18 57 48 83 EC 40 33 F6 48 89 6C 24 58"
    ),
}

PROFILE_RVAS = [
    0x4868C80, 0x4868CA0, 0x4868D50, 0x4868D90, 0x48691A0, 0x4869520,
    0x4869A30, 0x4869A50, 0x4869BD0, 0x4869CA0, 0x4869EA0, 0x486A0C0,
    0x486D140, 0x486ED70, 0x486E5E0, 0x486F0A0, 0x486F0E0, 0x4870960,
    PCALL_RVA,
]


def parse_rva(s) -> int:
    if isinstance(s, int):
        return s & 0xFFFFFFFFFFFFFFFF
    s = str(s).strip().lower()
    if s.startswith("0x-") or s.startswith("-0x"):
        return int(s.replace("0x", ""), 16) & 0xFFFFFFFFFFFFFFFF
    if s.startswith("0x"):
        return int(s, 16) & 0xFFFFFFFFFFFFFFFF
    if s.startswith("-"):
        return int(s, 0) & 0xFFFFFFFFFFFFFFFF
    if all(c in "0123456789abcdef" for c in s):
        return int(s, 16) & 0xFFFFFFFFFFFFFFFF
    return int(s, 0) & 0xFFFFFFFFFFFFFFFF


def rva_hex(r: int) -> str:
    return f"0x{(r & 0xFFFFFFFFFFFFFFFF):X}"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_hex_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split() if x)


class ImageView:
    """Sparse VA-mapped image (key = file-offset-from-image-base / rva)."""

    def __init__(self, image_base: int = IMAGE_BASE):
        self.image_base = image_base
        self.pages: Dict[int, bytes] = {}  # page_rva -> 0x1000 bytes (partial ok)

    def add(self, rva: int, data: bytes) -> None:
        # store spanning pages
        i = 0
        while i < len(data):
            page = (rva + i) & ~0xFFF
            off = (rva + i) - page
            take = min(0x1000 - off, len(data) - i)
            prev = self.pages.get(page, b"\x00" * 0x1000)
            buf = bytearray(prev)
            buf[off : off + take] = data[i : i + take]
            self.pages[page] = bytes(buf)
            i += take

    def read(self, rva: int, n: int) -> Optional[bytes]:
        out = bytearray()
        left = n
        cur = rva
        while left > 0:
            page = cur & ~0xFFF
            off = cur - page
            chunk = self.pages.get(page)
            if chunk is None:
                return None if not out else bytes(out)
            take = min(0x1000 - off, left)
            out += chunk[off : off + take]
            cur += take
            left -= take
        return bytes(out)

    def has(self, rva: int, n: int = 1) -> bool:
        return self.read(rva, n) is not None


def load_probe_into_view(probe: dict, view: ImageView) -> None:
    # first32 of nearby targets
    for x in probe.get("pcall_xrefs", []):
        for nt in x.get("nearby_call_targets", []):
            rva = parse_rva(nt["rva"])
            raw = parse_hex_bytes(nt["first32"])
            view.add(rva, raw)
        # before/after around pcall call site — reconstruct approximate window
        call_rva = parse_rva(x["call_rva"])
        before = parse_hex_bytes(x.get("before_hex", ""))
        after = parse_hex_bytes(x.get("after_hex", ""))
        # before_hex ends at call site; after starts after E8 rel32 (5 bytes)
        if before:
            view.add(call_rva - len(before), before)
        # call instruction itself not fully present — ok
        if after:
            view.add(call_rva + 5, after)
    # known first32 overrides (complete known prologues)
    for rva, raw in KNOWN_FIRST32.items():
        view.add(rva, raw)
    # string anchors — only addresses known; content not needed for disasm


def try_read_process(pid: int, rvas: List[int], nbytes: int = 0x200) -> ImageView:
    """Read selected RVAs from live process (needs PROCESS_VM_READ)."""
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
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
    CloseHandle = kernel32.CloseHandle

    h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        raise OSError(f"OpenProcess failed err={ctypes.get_last_error()} (run as Admin?)")

    view = ImageView()
    try:
        for rva in rvas:
            va = IMAGE_BASE + rva
            buf = (ctypes.c_ubyte * nbytes)()
            read = ctypes.c_size_t(0)
            ok = ReadProcessMemory(h, ctypes.c_void_p(va), buf, nbytes, ctypes.byref(read))
            if ok and read.value:
                view.add(rva, bytes(buf[: read.value]))
    finally:
        CloseHandle(h)
    return view


def make_md() -> Cs:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def disasm_at(view: ImageView, md: Cs, rva: int, max_bytes: int = 0x180) -> List[dict]:
    data = view.read(rva, max_bytes)
    if not data:
        return []
    out = []
    for insn in md.disasm(data, IMAGE_BASE + rva):
        out.append(
            {
                "rva": rva_hex(insn.address - IMAGE_BASE),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(" "),
                "size": insn.size,
            }
        )
        if insn.mnemonic in ("ret", "retn") and len(out) > 4:
            break
        if len(out) >= 120:
            break
    return out


def direct_calls(view: ImageView, md: Cs, rva: int, max_bytes: int = 0x180) -> List[dict]:
    data = view.read(rva, max_bytes)
    if not data:
        return []
    calls = []
    for insn in md.disasm(data, IMAGE_BASE + rva):
        if insn.mnemonic != "call":
            if insn.mnemonic in ("ret", "retn") and calls:
                break
            continue
        if len(insn.bytes) == 5 and insn.bytes[0] == 0xE8:
            rel = struct.unpack("<i", insn.bytes[1:5])[0]
            target_va = (insn.address + 5 + rel) & 0xFFFFFFFFFFFFFFFF
            target_rva = (target_va - IMAGE_BASE) & 0xFFFFFFFFFFFFFFFF
            if target_rva > 0x10000000:
                continue
            calls.append(
                {
                    "call_rva": rva_hex(insn.address - IMAGE_BASE),
                    "target_rva": rva_hex(target_rva),
                }
            )
        if len(calls) > 30:
            break
    return calls


def pattern_from_bytes(raw: bytes, max_len: int = 28) -> str:
    parts = []
    i = 0
    n = min(len(raw), max_len)
    while i < n:
        b = raw[i]
        if b in (0xE8, 0xE9) and i + 5 <= n:
            parts.append(f"{b:02X}")
            parts.extend(["??"] * 4)
            i += 5
            continue
        if b in (0x48, 0x4C) and i + 7 <= n and raw[i + 1] == 0x8D:
            modrm = raw[i + 2]
            if (modrm & 0xC7) == 0x05:
                parts += [f"{raw[i]:02X}", f"{raw[i+1]:02X}", f"{raw[i+2]:02X}", "??", "??", "??", "??"]
                i += 7
                continue
        parts.append(f"{b:02X}")
        i += 1
    return " ".join(parts)


def classify(insns: List[dict], calls: List[dict]) -> Tuple[List[str], int, str, str, List[str]]:
    tags: List[str] = []
    conf = 0
    kind = "unknown"
    proto = "unknown"
    evidence: List[str] = []
    if not insns:
        return ["no_bytes"], 0, kind, proto, ["no readable bytes at RVA"]

    head = " ".join(i["bytes"] for i in insns[:12]).lower()
    # strlen(RDX)
    if "48 c7 c0 ff ff ff ff" in head and any(
        "80 3c 02 00" in i["bytes"] or i["bytes"].startswith("80 3c 02") for i in insns[:20]
    ):
        tags.append("strlen_on_rdx")
        conf += 30
        evidence.append("prologue: rax=-1; inc; cmp [rdx+rax],0 — strlen(RDX)")

    if insns[0]["bytes"].startswith("48 83 ec 48"):
        tags.append("frame_0x48")
        conf += 5

    if any("44 24 70" in i["bytes"] for i in insns[:10]):
        tags.append("reads_stack_arg_0x70")
        conf += 25
        evidence.append("early read [rsp+0x70] after sub rsp,48 => 5th arg (mode)")

    if any(i["mnemonic"] == "lea" and "rip" in i["op_str"] for i in insns[:20]):
        tags.append("rip_relative_lea")
        conf += 5
        for i in insns[:20]:
            if i["mnemonic"] == "lea" and "rip" in i["op_str"]:
                evidence.append(f"lea {i['op_str']} @ {i['rva']}")

    # call chain
    call_tgts = [parse_rva(c["target_rva"]) for c in calls]
    if 0x486F0A0 in call_tgts:
        tags.append("calls_F0A0")
        conf += 35
        evidence.append("direct call to 0x486F0A0")
    if PCALL_RVA in call_tgts:
        tags.append("calls_pcallk")
        conf += 20
        evidence.append("direct call to lua_pcallk")

    # decide kind
    if "strlen_on_rdx" in tags and "calls_F0A0" in tags:
        kind = "luaL_loadstring"
        proto = "int __cdecl(lua_State* L /*rcx*/, const char* s /*rdx*/)"
        conf = max(conf, 88)
        evidence.append("loadstring pattern: strlen(s) then loadbufferx-like callee")
    elif "reads_stack_arg_0x70" in tags and "rip_relative_lea" in tags:
        kind = "luaL_loadbufferx"
        proto = (
            "int __cdecl(lua_State* L /*rcx*/, const char* buff /*rdx*/, "
            "size_t sz /*r8*/, const char* name /*r9*/, const char* mode /*[rsp+0x28]*/)"
        )
        conf = max(conf, 85)
        evidence.append("5-arg frame + RIP lea matches luaL_loadbufferx layout")
    elif "strlen_on_rdx" in tags:
        kind = "luaL_loadstring_or_wrapper"
        proto = "int __cdecl(lua_State* L /*rcx*/, const char* s /*rdx*/) [partial]"
        conf = max(conf, 60)

    if not tags:
        tags = ["unknown"]
    return tags, conf, kind, proto, evidence


def analyze_from_view(view: ImageView, probe: dict) -> dict:
    md = make_md()
    pcall_rva = parse_rva(probe.get("exact_scan", {}).get("lua_pcallk", {}).get("rva", PCALL_RVA))

    # collect rvas
    rvas = set(PROFILE_RVAS)
    for x in probe.get("pcall_xrefs", []):
        for nt in x.get("nearby_call_targets", []):
            rvas.add(parse_rva(nt["rva"]))

    functions = {}
    for rva in sorted(rvas):
        insns = disasm_at(view, md, rva)
        calls = direct_calls(view, md, rva)
        tags, conf, kind, proto, evidence = classify(insns, calls)
        raw = view.read(rva, 32) or b""
        functions[rva_hex(rva)] = {
            "rva": rva_hex(rva),
            "function_start_rva": rva_hex(rva),  # probe first32 already at function entry
            "instructions": insns[:50],
            "direct_calls": calls,
            "classification": tags,
            "kind_hypothesis": kind,
            "prototype_hypothesis": proto,
            "confidence": conf,
            "evidence": evidence,
            "first_bytes": raw.hex(" "),
            "signature_candidate": pattern_from_bytes(raw, 28) if raw else "",
            "bytes_available": len(raw),
        }

    # pcall xref: look for F0E0/F0A0 in nearby
    xref_hits = []
    for x in probe.get("pcall_xrefs", []):
        nearby = [parse_rva(t["rva"]) for t in x.get("nearby_call_targets", [])]
        hit = {
            "pcall_call_rva": x["call_rva"],
            "nearby": [rva_hex(n) for n in nearby],
            "has_F0E0": 0x486F0E0 in nearby,
            "has_F0A0": 0x486F0A0 in nearby,
        }
        # disasm before window end for test eax,eax after load
        call_rva = parse_rva(x["call_rva"])
        after = parse_hex_bytes(x.get("after_hex", ""))
        if after[:2] == bytes.fromhex("85 C0"):
            hit["after_test_eax"] = True
        xref_hits.append(hit)

    # deep candidates
    loader_candidates = []
    for rva, name in [(0x486F0E0, "cand_F0E0"), (0x486F0A0, "cand_F0A0")]:
        f = functions.get(rva_hex(rva), {})
        # who lists them near pcall
        callers = [h["pcall_call_rva"] for h in xref_hits if (name.endswith("F0E0") and h["has_F0E0"]) or (name.endswith("F0A0") and h["has_F0A0"])]
        # signature uniqueness cannot be proven without full .text; mark unknown unless dump
        sig = f.get("signature_candidate", "")
        loader_candidates.append(
            {
                "name": name,
                "rva": rva_hex(rva),
                "kind_hypothesis": f.get("kind_hypothesis"),
                "prototype_hypothesis": f.get("prototype_hypothesis"),
                "confidence": f.get("confidence", 0),
                "evidence": f.get("evidence", []),
                "classification": f.get("classification", []),
                "direct_calls": f.get("direct_calls", []),
                "callers_near_pcall": callers,
                "signature_pattern": sig,
                "signature_matches": None,  # needs full image
                "instructions": f.get("instructions", [])[:40],
                "bytes_available": f.get("bytes_available", 0),
            }
        )

    # chain check: F0E0 calls F0A0?
    f0e0 = next(c for c in loader_candidates if c["name"] == "cand_F0E0")
    f0a0 = next(c for c in loader_candidates if c["name"] == "cand_F0A0")
    chain = None
    if any(parse_rva(c["target_rva"]) == 0x486F0A0 for c in f0e0.get("direct_calls", [])):
        chain = "0x486F0E0 (luaL_loadstring) -> 0x486F0A0 (luaL_loadbufferx)"
        f0e0["confidence"] = max(f0e0["confidence"], 90)
        f0a0["confidence"] = max(f0a0["confidence"], 90)
        f0e0["kind_hypothesis"] = "luaL_loadstring"
        f0a0["kind_hypothesis"] = "luaL_loadbufferx"

    # Also: if F0E0 has strlen and first call target readable as F0A0 from known call encoding
    # From probe first32 of F0E0 we can decode remaining with process/dump only.

    # string anchors
    strings = {}
    for s in probe.get("string_anchors", []):
        strings[s["string"]] = {"string_rva": s["rva"], "code_xrefs": "requires_full_image"}

    # Winner policy: prefer loadbufferx as inject adapter (can implement loadstring via it)
    winner = None
    enable = False
    if f0a0["kind_hypothesis"] == "luaL_loadbufferx" and f0a0["confidence"] >= 80:
        winner = {
            "loader_rva": f0a0["rva"],
            "kind": "luaL_loadbufferx",
            "prototype": f0a0["prototype_hypothesis"],
            "signature_pattern": f0a0["signature_pattern"],
            "confidence": f0a0["confidence"],
            "secondary_loadstring_wrapper": f0e0["rva"] if f0e0["kind_hypothesis"] == "luaL_loadstring" else None,
            "chain": chain,
            # Do NOT enable runtime until signature_matches==1 on full image
            "enable_runtime": False,
            "blockers": [
                "signature unique-count not proven on full .text (packed on-disk PE)",
                "need process dump or Admin --pid full-page read to finalize pattern uniqueness",
            ],
        }
    elif f0e0["kind_hypothesis"] in ("luaL_loadstring", "luaL_loadstring_or_wrapper") and f0e0["confidence"] >= 70:
        winner = {
            "loader_rva": f0e0["rva"],
            "kind": f0e0["kind_hypothesis"],
            "prototype": f0e0["prototype_hypothesis"],
            "signature_pattern": f0e0["signature_pattern"],
            "confidence": f0e0["confidence"],
            "enable_runtime": False,
            "blockers": ["prefer loadbufferx if available; uniqueness unproven"],
        }

    return {
        "schema_version": 1,
        "source": "probe_hex+optional_process",
        "image_base": rva_hex(IMAGE_BASE),
        "lua_pcallk_rva": rva_hex(pcall_rva),
        "functions": functions,
        "pcall_xref_flags": xref_hits,
        "loader_candidates": loader_candidates,
        "string_anchors": strings,
        "conclusion": {
            "winner": winner,
            "chain": chain,
            "legacy_lua_load_matches": probe.get("exact_scan", {}).get("lua_load", {}).get("matches", 0),
            "enable_runtime_hook": enable,
            "rejected_hypotheses": [
                {"rva": "0x4868C80", "reason": "top/stack pointer arithmetic helper"},
                {"rva": "0x4868CA0", "reason": "stack index helper"},
                {"rva": "0x4868D50", "reason": "TValue move helper"},
                {"rva": "0x4868D90", "reason": "stack access helper"},
            ],
            "notes": [
                "On-disk wwm.exe is packed (section raw sizes 0) — cannot scan .text from file.",
                "Runtime enable requires unique signature match on live image + fingerprint.",
                "UPLOAD_SCHEMA_VERIFIED remains false.",
            ],
        },
    }


def write_report(path: str, result: dict, sha: str) -> None:
    w = result["conclusion"].get("winner") or {}
    lines = [
        "# C6 — WWM Lite Lua loader analysis",
        "",
        f"**Module SHA-256 (on-disk fingerprint):** `{sha}`",
        f"**lua_pcallk RVA:** `{result['lua_pcallk_rva']}`",
        f"**Legacy lua_load matches:** {result['conclusion'].get('legacy_lua_load_matches')}",
        f"**Analysis source:** `{result.get('source')}`",
        "",
        "## Important constraint",
        "",
        "On-disk `wwm.exe` is **packed** (PE sections have `RawSize=0`).",
        "Probe bytes come from **runtime** image at base `0x140000000`.",
        "Exact signature uniqueness requires process memory or an unpacked dump — not the packed file.",
        "",
        "## Conclusion",
        "",
    ]
    if w:
        lines += [
            f"- **Best candidate kind:** `{w.get('kind')}`",
            f"- **RVA:** `{w.get('loader_rva')}`",
            f"- **Prototype:** `{w.get('prototype')}`",
            f"- **Confidence:** {w.get('confidence')}",
            f"- **Chain:** {w.get('chain')}",
            f"- **Enable runtime:** `{w.get('enable_runtime')}`",
            f"- **Pattern (provisional):** `{w.get('signature_pattern')}`",
            f"- **Blockers:** {w.get('blockers')}",
            "",
        ]
    else:
        lines += ["- No winner yet.", ""]

    lines += ["## Candidates", ""]
    for c in result.get("loader_candidates", []):
        lines += [
            f"### {c['name']} @ {c['rva']}",
            f"- kind: `{c['kind_hypothesis']}` conf={c['confidence']}",
            f"- proto: `{c['prototype_hypothesis']}`",
            f"- callers_near_pcall: {c.get('callers_near_pcall')}",
            f"- pattern: `{c.get('signature_pattern')}`",
            "- evidence:",
        ]
        for e in c.get("evidence", []):
            lines.append(f"  - {e}")
        lines.append("- first instructions:")
        for i in c.get("instructions", [])[:20]:
            lines.append(f"  - `{i['rva']}`: {i['mnemonic']} {i['op_str']}")
        lines.append("")

    lines += [
        "## pcall xrefs touching candidates",
        "",
    ]
    for h in result.get("pcall_xref_flags", []):
        if h.get("has_F0E0") or h.get("has_F0A0"):
            lines.append(
                f"- pcall @{h['pcall_call_rva']}: F0E0={h['has_F0E0']} F0A0={h['has_F0A0']} after_test_eax={h.get('after_test_eax')}"
            )
    lines += [
        "",
        "## Rejected",
        "",
    ]
    for r in result["conclusion"].get("rejected_hypotheses", []):
        lines.append(f"- {r['rva']}: {r['reason']}")
    lines += [
        "",
        "## Runtime enable criteria (not met yet)",
        "",
        "1. module sha256 match",
        "2. exact signature match count == 1 on **runtime** image",
        "3. pcall match == 1",
        "4. prototype proven",
        "",
        "UPLOAD_SCHEMA_VERIFIED remains false.",
        "",
    ]
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", required=True, help="Path to wwm.exe (for SHA-256 fingerprint)")
    ap.add_argument("--probe", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", default=None)
    ap.add_argument("--expect-sha256", default=EXPECTED_SHA256)
    ap.add_argument("--pid", type=int, default=None, help="Optional running wwm PID for VM reads")
    args = ap.parse_args()

    digest = sha256_file(args.module)
    if args.expect_sha256 and digest.lower() != args.expect_sha256.lower():
        print(f"BUILD_FINGERPRINT_MISMATCH got={digest} expected={args.expect_sha256}")
        return 3

    with open(args.probe, "r", encoding="utf-8") as f:
        probe = json.load(f)

    view = ImageView()
    load_probe_into_view(probe, view)

    if args.pid:
        try:
            rvas = list(PROFILE_RVAS)
            for x in probe.get("pcall_xrefs", []):
                for nt in x.get("nearby_call_targets", []):
                    rvas.append(parse_rva(nt["rva"]))
            # also read a bit more for F0E0/F0A0 full bodies
            proc_view = try_read_process(args.pid, sorted(set(rvas)), nbytes=0x200)
            for page, data in proc_view.pages.items():
                view.add(page, data)
            print(f"[+] Merged process memory pages from pid={args.pid}: {len(proc_view.pages)}")
        except OSError as e:
            print(f"[!] process read failed: {e}")

    result = analyze_from_view(view, probe)
    result["sha256"] = digest
    result["module_path"] = args.module
    result["packed_on_disk"] = True

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"[+] Wrote {args.out}")

    if args.report:
        write_report(args.report, result, digest)
        print(f"[+] Wrote {args.report}")

    w = result["conclusion"].get("winner")
    if w:
        print(
            f"[*] Best: {w.get('kind')} @ {w.get('loader_rva')} conf={w.get('confidence')} "
            f"enable={w.get('enable_runtime')} chain={w.get('chain')}"
        )
    else:
        print("[*] No winner — analysis only")
    print("[*] enable_runtime_hook=false (signature uniqueness not proven on packed PE)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
