#!/usr/bin/env python3
"""
Verify (or reject) WWM Lite loader hypothesis using probe call-site windows.

Does NOT enable runtime hooks. Does NOT require process memory for the
load→pcall flow proof (that is visible in probe before_hex/after_hex).

Signature uniqueness still requires live image (--pid) or unpacked dump.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    print("pip install -r requirements-hook-analysis.txt", file=sys.stderr)
    sys.exit(2)

PCALL = 0x486C270
F0A0 = 0x486F0A0
F0E0 = 0x486F0E0
BASE = 0x140000000
EXPECTED_SHA = "0cfdfcc69d543af7428aac39f8bc3ea5db42563b84101b775ab710a6d050e8b1"

KNOWN_FIRST32 = {
    F0E0: bytes.fromhex(
        "48 83 EC 48 48 89 54 24 30 48 C7 C0 FF FF FF FF "
        "48 FF C0 80 3C 02 00 75 F7 4C 8B CA 48 89 44 24"
    ),
    F0A0: bytes.fromhex(
        "48 83 EC 48 48 8B 44 24 70 48 89 54 24 30 48 8D 15 "
        "EB 10 00 00 4C 89 44 24 38 4C 8D 44 24 30 48"
    ),
}


def parse_hex(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split())


def s32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v


def find_e8_targets(call_rva: int, before: bytes) -> List[Tuple[int, int]]:
    out = []
    for i in range(len(before) - 4):
        if before[i] != 0xE8:
            continue
        e8_rva = call_rva - (len(before) - i)
        rel = struct.unpack_from("<i", before, i + 1)[0]
        tgt = (e8_rva + 5 + rel) & 0xFFFFFFFFFFFFFFFF
        if tgt < 0x10000000:
            out.append((e8_rva, tgt))
    return out


def disasm_window(md: Cs, start_rva: int, data: bytes) -> List[dict]:
    rows = []
    for insn in md.disasm(data, BASE + start_rva):
        rows.append(
            {
                "rva": f"0x{insn.address - BASE:X}",
                "text": f"{insn.mnemonic} {insn.op_str}".strip(),
                "bytes": insn.bytes.hex(" "),
            }
        )
    return rows


def analyze_caller(md: Cs, x: dict) -> Optional[dict]:
    call_rva = int(x["call_rva"], 16)
    before = parse_hex(x.get("before_hex", ""))
    after = parse_hex(x.get("after_hex", ""))
    e8s = find_e8_targets(call_rva, before)
    loader_hits = [(a, t) for a, t in e8s if t in (F0A0, F0E0)]
    if not loader_hits:
        return None

    # Reconstruct: before + E8(pcall) + after
    rel = s32(PCALL - (call_rva + 5))
    blob_start = call_rva - len(before)
    blob = before + b"\xE8" + struct.pack("<i", rel) + after[:64]
    insns = disasm_window(md, blob_start, blob)

    # Find loader call then pcall; check test eax between / after
    flow = []
    saw_loader = None
    test_after_loader = False
    pcall_after_ok = False
    test_after_pcall = False
    mode_stack_zero = False
    arg_notes = []

    for i, row in enumerate(insns):
        r = int(row["rva"], 16)
        t = row["text"]
        for _, tgt in loader_hits:
            if f"0x{BASE + tgt:x}" in t.lower() or f"0x{tgt:x}" in t.lower():
                # capstone prints full VA
                if t.startswith("call"):
                    saw_loader = tgt
                    flow.append(f"{row['rva']}: call loader {hex(tgt)}")
                    # look ahead for test eax
                    for j in range(i + 1, min(i + 6, len(insns))):
                        if insns[j]["text"].startswith("test eax, eax") or insns[j][
                            "text"
                        ].startswith("test eax,eax"):
                            test_after_loader = True
                            flow.append(f"{insns[j]['rva']}: test eax,eax (loader status)")
                            break
        if r == call_rva and t.startswith("call"):
            flow.append(f"{row['rva']}: call lua_pcallk")
            if saw_loader is not None:
                pcall_after_ok = True
            for j in range(i + 1, min(i + 4, len(insns))):
                if "test eax" in insns[j]["text"]:
                    test_after_pcall = True
                    flow.append(f"{insns[j]['rva']}: test eax,eax (pcall status)")
                    break

    # Arg setup heuristics in before window (last 40 bytes / last insns)
    for row in insns:
        r = int(row["rva"], 16)
        if saw_loader is None:
            continue
        # only before loader call
        # crude: collect mov/lea with rcx/rdx/r8/r9/rsp+20
        if "call" in row["text"] and hex(saw_loader)[2:] in row["text"].replace("0x", ""):
            break
        if any(
            k in row["text"]
            for k in ("rcx", "rdx", "r8", "r9", "rsp + 0x20", "[rsp + 0x20]")
        ):
            arg_notes.append(f"{row['rva']}: {row['text']}")
        if "qword ptr [rsp + 0x20], 0" in row["text"] or row["text"] == "mov qword ptr [rsp + 0x20], 0":
            mode_stack_zero = True

    # Capstone VA form: call 0x14486f0a0
    for row in insns:
        if row["text"].startswith("call") and (
            f"{BASE + F0A0:x}" in row["text"] or f"{BASE + F0E0:x}" in row["text"]
        ):
            # re-walk args immediately before this insn
            idx = insns.index(row)
            arg_notes = []
            for j in range(max(0, idx - 12), idx):
                arg_notes.append(f"{insns[j]['rva']}: {insns[j]['text']}")
                if "qword ptr [rsp + 0x20], 0" in insns[j]["text"]:
                    mode_stack_zero = True
            break

    return {
        "pcall_call_rva": f"0x{call_rva:X}",
        "loader_calls": [{"call_rva": f"0x{a:X}", "target": f"0x{t:X}"} for a, t in loader_hits],
        "test_eax_after_loader": test_after_loader,
        "pcall_after_loader_success_path": pcall_after_ok and test_after_loader,
        "test_eax_after_pcall": test_after_pcall,
        "mode_stack_arg_zero": mode_stack_zero,
        "arg_setup_near_loader": arg_notes[-12:],
        "flow": flow,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--module-sha256", default=EXPECTED_SHA)
    args = ap.parse_args()

    probe = json.load(open(args.probe, encoding="utf-8"))
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    callers = []
    for x in probe.get("pcall_xrefs", []):
        info = analyze_caller(md, x)
        if info:
            callers.append(info)

    f0e0_callers = [c for c in callers if any(x["target"] == "0x486F0E0" for x in c["loader_calls"])]
    f0a0_callers = [c for c in callers if any(x["target"] == "0x486F0A0" for x in c["loader_calls"])]

    # Proven facts from disasm of known first32
    f0e0_body = {
        "rva": "0x486F0E0",
        "known_bytes": KNOWN_FIRST32[F0E0].hex(" "),
        "observations": [
            "sub rsp, 0x48",
            "mov [rsp+0x30], rdx  ; save s",
            "rax=-1; inc; cmp [rdx+rax],0; jne  ; strlen(RDX)",
            "mov r9, rdx  ; (partial — body truncated after this in probe)",
        ],
        "strlen_on_rdx": True,
        "calls_F0A0_proven": False,  # body truncated; not visible in first32
        "body_complete": False,
    }

    f0a0_body = {
        "rva": "0x486F0A0",
        "known_bytes": KNOWN_FIRST32[F0A0].hex(" "),
        "observations": [
            "sub rsp, 0x48",
            "mov rax, [rsp+0x70]  ; 5th arg after frame (mode)",
            "mov [rsp+0x30], rdx  ; save buff",
            "lea rdx, [rip+0x10eb]  ; constant",
            "mov [rsp+0x38], r8  ; save size",
            "lea r8, [rsp+0x30]",
            "body truncated after ~31 bytes in probe first32",
        ],
        "reads_5th_stack_arg": True,
        "body_complete": False,
    }

    # Prototype from callers (not prologue alone)
    # Strongest F0A0 caller: 0x214FD3B window shows:
    #   mov rbx, rcx / mov [rsp+20h], 0 / call F0A0 / test eax / pcall
    f0a0_proto = {
        "rcx": "lua_State* L (saved to rbx, reused for pcall)",
        "rdx": "preserved into F0A0 (buff) — not overwritten in thin wrapper 0x214FD00",
        "r8": "preserved (size); wrapper does mov r8d,r8d",
        "r9": "preserved (name) — not set in thin wrapper",
        "stack_arg5": "mode; explicit 0 at [rsp+0x20] before call F0A0 in 0x214FD00",
        "return": "Lua status in EAX; test eax,eax then conditional pcall",
        "callers_examined": [c["pcall_call_rva"] for c in f0a0_callers],
    }

    f0e0_proto = {
        "rcx": "lua_State* L (mov rcx, rdi before call at 0x1F7EE86)",
        "rdx": "const char* s (lea rdx, [rsp+40h] or mov rdx, rbx)",
        "r8": "not set by callers — computed inside via strlen",
        "r9": "unknown until full body (partial mov r9,rdx at end of first32)",
        "stack_arg5": "unknown until full body",
        "return": "Lua status in EAX; test eax,eax then pcall on success",
        "callers_examined": [c["pcall_call_rva"] for c in f0e0_callers],
    }

    pcall_flow_verified = any(c["pcall_after_loader_success_path"] for c in callers)
    # require at least one clean F0A0 and one F0E0 path with test eax
    pcall_flow_f0a0 = any(c["test_eax_after_loader"] and c["pcall_after_loader_success_path"] for c in f0a0_callers)
    pcall_flow_f0e0 = any(c["test_eax_after_loader"] and c["pcall_after_loader_success_path"] for c in f0e0_callers)

    loadstring_calls_loader = False  # not proven without full F0E0 body

    # signature uniqueness unknown offline
    signature_matches = None

    # "=(load)" xref not found in pcall windows
    load_string_xref_verified = False

    confidence = 0
    evidence = []
    if pcall_flow_f0a0:
        confidence += 30
        evidence.append("F0A0→test eax→lua_pcallk verified at one or more call sites")
    if pcall_flow_f0e0:
        confidence += 25
        evidence.append("F0E0→test eax→lua_pcallk verified at one or more call sites")
    if any(c.get("mode_stack_arg_zero") for c in f0a0_callers):
        confidence += 15
        evidence.append("F0A0 caller sets [rsp+0x20]=0 (mode NULL) before call")
    if f0e0_body["strlen_on_rdx"]:
        confidence += 10
        evidence.append("F0E0 prologue is strlen(RDX)")
    if f0a0_body["reads_5th_stack_arg"]:
        confidence += 10
        evidence.append("F0A0 prologue reads [rsp+0x70] (5th arg after sub rsp,48)")
    evidence.append("F0E0 body after strlen truncated — cannot prove call to F0A0")
    evidence.append("F0A0 body after ~31 bytes truncated — cannot prove inner lua_load")
    evidence.append("signature unique-count not proven (packed on-disk PE)")
    evidence.append("=(load) code xrefs not found in pcall windows")

    # Cap confidence without uniqueness + full body
    confidence = min(confidence, 85)

    verified = bool(
        pcall_flow_f0a0
        and f0a0_proto["return"].startswith("Lua status")
        and signature_matches == 1
        and loadstring_calls_loader  # optional but we require strong chain OR full body
    )
    # Explicit: we do NOT verify fully without signature_matches==1
    verified = False

    report = {
        "verified": verified,
        "module_sha256": args.module_sha256,
        "loader_rva": "0x486F0A0",
        "loader_kind": "luaL_loadbufferx" if pcall_flow_f0a0 else "unknown",
        "prototype": (
            "int __cdecl(lua_State* L, const char* buff, size_t size, "
            "const char* name, const char* mode)"
        ),
        "prototype_detail": f0a0_proto,
        "loadstring_wrapper_rva": "0x486F0E0",
        "loadstring_prototype_detail": f0e0_proto,
        "loadstring_calls_loader": loadstring_calls_loader,
        "pcall_flow_verified": pcall_flow_verified,
        "pcall_flow_f0a0": pcall_flow_f0a0,
        "pcall_flow_f0e0": pcall_flow_f0e0,
        "load_string_xref_verified": load_string_xref_verified,
        "signature_matches": signature_matches,
        "signature_pattern_provisional": (
            "48 83 EC 48 48 8B 44 24 70 48 89 54 24 30 48 8D 15 ?? ?? ?? ?? "
            "4C 89 44 24 38 4C 8D 44 24 30"
        ),
        "confidence": confidence,
        "enable_runtime": False,
        "blockers": [
            "signature_matches not proven on full runtime .text (packed PE on disk)",
            "F0A0 function body incomplete in probe (31 bytes)",
            "F0E0→F0A0 call not visible (F0E0 body truncated after strlen)",
            "=(load) string code xrefs not verified",
        ],
        "evidence": evidence,
        "f0a0_body": f0a0_body,
        "f0e0_body": f0e0_body,
        "callers": callers,
        "lua_pcallk_rva": "0x486C270",
        "legacy_lua_load_matches": probe.get("exact_scan", {}).get("lua_load", {}).get("matches", 0),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(json.dumps({k: report[k] for k in [
        "verified", "loader_rva", "loader_kind", "loadstring_calls_loader",
        "pcall_flow_verified", "pcall_flow_f0a0", "pcall_flow_f0e0",
        "load_string_xref_verified", "signature_matches", "confidence", "enable_runtime",
    ]}, indent=2))
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
