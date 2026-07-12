#!/usr/bin/env python3
"""
Download a CN face short-code object and write a pending conversion payload.

  py Scripts/prepare_cn_to_global.py yysls_facedata_R37_<OBJECT_KEY>

Writes captures/pending_cn_to_global.json (armed=false).
Never prints full face_data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

CN_PREFIX = "yysls_facedata_R37_"
# Same morphology as src/config/regions.js FP_OBJECT_KEY_RE
OBJECT_KEY_RE = re.compile(r"^[0-9a-f]{24}[A-Za-z0-9]{8}[0-9]{2}$")
ALLOW_HOST = "h72.fp.ps.netease.com"
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 30
FACE_PREFIX_RE = re.compile(r"^[RD]67", re.I)


def fail(msg: str, code: int = 2) -> None:
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def parse_code(code: str) -> str:
    raw = code.strip()
    if not raw.startswith(CN_PREFIX):
        fail(f"code must start with {CN_PREFIX}")
    key = raw[len(CN_PREFIX) :]
    if not OBJECT_KEY_RE.match(key):
        fail("invalid object key morphology (expected 24hex+8alnum+2digit)")
    if len(key) > 64:
        fail("object key too long")
    return key


def download(key: str) -> dict:
    url = f"https://{ALLOW_HOST}/file/{key}"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "find-api-prepare-cn-to-global/1.0",
            "Accept": "application/json,text/plain,*/*",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            final = resp.geturl()
            if ALLOW_HOST not in final:
                fail(f"redirect left allowlist: {final}")
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "html" in ctype:
                fail(f"HTML content-type rejected: {ctype}")
            data = resp.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        fail(f"HTTP {e.code} from CDN")
    except urllib.error.URLError as e:
        fail(f"network error: {e.reason}")
    if len(data) > MAX_BYTES:
        fail(f"response exceeds {MAX_BYTES} bytes")
    if b"<html" in data[:200].lower():
        fail("HTML body rejected")
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception as e:
        fail(f"invalid JSON: {e}")
    if not isinstance(obj, dict):
        fail("CDN body must be a JSON object")
    return obj


def validate_payload(obj: dict) -> tuple[str, object]:
    for bad in ("token", "session", "cookie", "authorization", "Authorization"):
        if bad in obj:
            fail(f"refusing payload with secret-like field: {bad}")
    face = obj.get("face_data")
    if not isinstance(face, str) or not face.strip():
        fail("missing face_data string")
    face = face.replace("\r", "").replace("\n", "").replace("\t", "").replace(" ", "").strip()
    if not FACE_PREFIX_RE.match(face):
        fail("face_data must start with R67 or D67")
    if len(face) < 16 or len(face) > 500_000:
        fail(f"face_data length out of range: {len(face)}")
    dressing = obj.get("dressing")
    if dressing is None:
        fail("missing dressing")
    if isinstance(dressing, str):
        if len(dressing) > 500_000:
            fail("dressing string too large")
    elif isinstance(dressing, dict):
        raw = json.dumps(dressing, ensure_ascii=False, separators=(",", ":"))
        if len(raw) > 500_000:
            fail("dressing object too large")
    else:
        fail(f"dressing must be object or string, got {type(dressing).__name__}")
    return face, dressing


def main() -> int:
    ap = argparse.ArgumentParser(description="Prepare CN face for Global one-shot conversion")
    ap.add_argument("code", help="yysls_facedata_R37_<object_key>")
    ap.add_argument(
        "--out",
        default=None,
        help="output path (default: captures/pending_cn_to_global.json)",
    )
    args = ap.parse_args()

    key = parse_code(args.code)
    print(f"[*] object_key={key}")
    print(f"[*] GET https://{ALLOW_HOST}/file/{key}")
    obj = download(key)
    face, dressing = validate_payload(obj)
    face_hash = hashlib.sha256(face.encode("utf-8")).hexdigest()

    pending = {
        "schema_version": 1,
        "source_code_prefix": CN_PREFIX,
        "source_object_key": key,
        "source_region": "CN",
        "face_data": face,
        "dressing": dressing,
        "face_data_length": len(face),
        "face_data_hash": face_hash,
        "armed": False,
        "armed_at_unix": 0,
        "expires_in_seconds": 120,
    }

    root = Path(__file__).resolve().parents[1]
    out = Path(args.out) if args.out else root / "captures" / "pending_cn_to_global.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(pending, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[+] wrote {out}")
    print(f"    face_data_length={len(face)}")
    print(f"    face_data_hash={face_hash[:16]}...")
    print(f"    armed=false  (press F6 in-game with hook to arm)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(130)
