#include "hook/lua_signature_probe.h"
#include "hook/lua_signatures.h"
#include "pattern_scan.h"
#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "version.lib")

namespace face_capture {
namespace {

constexpr size_t kMaxJsonBytes = 2 * 1024 * 1024;
constexpr int kMaxFuzzy = 20;
constexpr int kMaxXrefs = 40;
constexpr int kMaxStringHits = 16;

struct JsonBuf {
  std::string s;
  bool truncated = false;
  void append(const char *p) {
    if (truncated)
      return;
    size_t n = strlen(p);
    if (s.size() + n > kMaxJsonBytes) {
      truncated = true;
      s += ",\"truncated\":true";
      return;
    }
    s.append(p, n);
  }
  void append(const std::string &x) { append(x.c_str()); }
};

std::string HexU64(uint64_t v) {
  char b[32];
  _snprintf_s(b, _TRUNCATE, "0x%llX", (unsigned long long)v);
  return b;
}

std::string HexBytes(const uint8_t *p, size_t n) {
  std::string o;
  o.reserve(n * 3);
  for (size_t i = 0; i < n; i++) {
    char b[4];
    _snprintf_s(b, _TRUNCATE, "%02X", p[i]);
    if (i)
      o += ' ';
    o += b;
  }
  return o;
}

std::string JsonEsc(const std::string &in) {
  std::string o;
  o.reserve(in.size() + 8);
  for (unsigned char c : in) {
    if (c == '"')
      o += "\\\"";
    else if (c == '\\')
      o += "\\\\";
    else if (c < 0x20) {
      char b[8];
      _snprintf_s(b, _TRUNCATE, "\\u%04x", c);
      o += b;
    } else
      o += (char)c;
  }
  return o;
}

std::string Sha256File(const char *path) {
  HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return {};
  BCRYPT_ALG_HANDLE alg = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  std::string out;
  do {
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
      break;
    DWORD objLen = 0, cb = 0, hashLen = 0;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0) != 0)
      break;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cb, 0) != 0)
      break;
    std::vector<uint8_t> obj(objLen);
    std::vector<uint8_t> dig(hashLen);
    if (BCryptCreateHash(alg, &hash, obj.data(), objLen, nullptr, 0, 0) != 0)
      break;
    uint8_t buf[1 << 16];
    DWORD rd = 0;
    BOOL ok = TRUE;
    while ((ok = ReadFile(h, buf, sizeof(buf), &rd, nullptr)) && rd) {
      if (BCryptHashData(hash, buf, rd, 0) != 0) {
        ok = FALSE;
        break;
      }
    }
    if (!ok)
      break;
    if (BCryptFinishHash(hash, dig.data(), hashLen, 0) != 0)
      break;
    out.reserve(hashLen * 2);
    for (DWORD i = 0; i < hashLen; i++) {
      char b[3];
      _snprintf_s(b, _TRUNCATE, "%02x", dig[i]);
      out += b;
    }
  } while (0);
  if (hash)
    BCryptDestroyHash(hash);
  if (alg)
    BCryptCloseAlgorithmProvider(alg, 0);
  CloseHandle(h);
  return out;
}

std::string FileVersionString(const char *path) {
  DWORD h = 0;
  DWORD sz = GetFileVersionInfoSizeA(path, &h);
  if (!sz)
    return {};
  std::vector<char> buf(sz);
  if (!GetFileVersionInfoA(path, 0, sz, buf.data()))
    return {};
  VS_FIXEDFILEINFO *fi = nullptr;
  UINT len = 0;
  if (!VerQueryValueA(buf.data(), "\\", (LPVOID *)&fi, &len) || !fi)
    return {};
  char o[64];
  _snprintf_s(o, _TRUNCATE, "%u.%u.%u.%u",
              (unsigned)((fi->dwFileVersionMS >> 16) & 0xFFFF),
              (unsigned)(fi->dwFileVersionMS & 0xFFFF),
              (unsigned)((fi->dwFileVersionLS >> 16) & 0xFFFF),
              (unsigned)(fi->dwFileVersionLS & 0xFFFF));
  return o;
}

bool ReadPeHeaders(const uint8_t *base, size_t imageSize, uint32_t &ts, uint32_t &textRva,
                   uint32_t &textSize) {
  ts = textRva = textSize = 0;
  if (imageSize < 0x200)
    return false;
  if (base[0] != 'M' || base[1] != 'Z')
    return false;
  uint32_t lfanew = *(const uint32_t *)(base + 0x3C);
  if (lfanew + 0x18 >= imageSize)
    return false;
  const uint8_t *nt = base + lfanew;
  if (nt[0] != 'P' || nt[1] != 'E')
    return false;
  ts = *(const uint32_t *)(nt + 8);
  uint16_t numSec = *(const uint16_t *)(nt + 6);
  uint16_t optSize = *(const uint16_t *)(nt + 20);
  const uint8_t *sec = nt + 24 + optSize;
  for (uint16_t i = 0; i < numSec; i++) {
    const uint8_t *s = sec + i * 40;
    if ((size_t)(s - base) + 40 > imageSize)
      break;
    char name[9] = {};
    memcpy(name, s, 8);
    if (strcmp(name, ".text") == 0) {
      textSize = *(const uint32_t *)(s + 8);
      textRva = *(const uint32_t *)(s + 12);
      return true;
    }
  }
  return true;
}

// Fuzzy: score = matching non-wildcard bytes; keep top K worst-mismatch (best scores).
struct FuzzyHit {
  uintptr_t addr = 0;
  int mismatches = 0;
  int compared = 0;
  std::string hex64;
};

std::vector<FuzzyHit> FuzzyScan(uintptr_t base, size_t size, const char *pattern, int maxOut) {
  std::vector<FuzzyHit> best;
  auto bytes = ParsePattern(pattern);
  if (bytes.empty() || !base || !size)
    return best;
  const size_t patLen = bytes.size();
  if (size < patLen)
    return best;

  // Hard caps: full .text on WWM Lite is ~200MB — never freeze the game.
  constexpr size_t kMaxFuzzyRegionBytes = 12 * 1024 * 1024; // 12MB total examined
  constexpr size_t kStride = 4;
  constexpr int kMaxMismatches = 6;
  constexpr uint64_t kMaxFirstHits = 500000;
  size_t examined = 0;
  uint64_t firstHits = 0;

  const uintptr_t end = base + size;
  uintptr_t addr = base;
  while (addr + patLen <= end && examined < kMaxFuzzyRegionBytes) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)))
      break;
    uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
    uintptr_t regionEnd = regionBase + mbi.RegionSize;
    if (regionEnd <= addr) {
      addr += 0x1000;
      continue;
    }
    const bool exec =
        mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
        (mbi.Protect &
         (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
    if (exec) {
      uintptr_t scanStart = addr > regionBase ? addr : regionBase;
      uintptr_t scanEnd = regionEnd < end ? regionEnd : end;
      if (scanEnd >= scanStart + patLen) {
        const uint8_t *p = (const uint8_t *)scanStart;
        size_t n = (size_t)(scanEnd - scanStart - patLen);
        for (size_t i = 0; i <= n; i += kStride) {
          if (examined >= kMaxFuzzyRegionBytes || firstHits >= kMaxFirstHits)
            break;
          examined += kStride;
          if (!bytes[0].wildcard && p[i] != bytes[0].value)
            continue;
          firstHits++;
          int mism = 0, cmp = 0;
          for (size_t j = 0; j < patLen; j++) {
            if (bytes[j].wildcard)
              continue;
            cmp++;
            if (p[i + j] != bytes[j].value) {
              mism++;
              if (mism > kMaxMismatches)
                break;
            }
          }
          if (cmp == 0 || mism > kMaxMismatches)
            continue;
          FuzzyHit h;
          h.addr = scanStart + i;
          h.mismatches = mism;
          h.compared = cmp;
          size_t dumpN = patLen < 64 ? patLen : 64;
          h.hex64 = HexBytes(p + i, dumpN);
          best.push_back(h);
          for (size_t a = best.size() - 1; a > 0; a--) {
            if (best[a].mismatches < best[a - 1].mismatches)
              std::swap(best[a], best[a - 1]);
            else
              break;
          }
          if ((int)best.size() > maxOut)
            best.pop_back();
        }
      }
    }
    if (regionEnd <= addr)
      break;
    addr = regionEnd;
  }
  return best;
}

struct XrefHit {
  uintptr_t call_site = 0;
  uintptr_t target = 0;
  std::string before_hex;
  std::string after_hex;
  std::vector<std::pair<uintptr_t, std::string>> nearby_targets; // addr, first32
};

std::vector<XrefHit> FindDirectCallXrefs(uintptr_t base, size_t size, uintptr_t target,
                                         int maxOut) {
  std::vector<XrefHit> out;
  if (!base || !size || !target)
    return out;
  const uintptr_t end = base + size;
  uintptr_t addr = base;
  while (addr + 5 <= end && (int)out.size() < maxOut) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)))
      break;
    uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
    uintptr_t regionEnd = regionBase + mbi.RegionSize;
    if (regionEnd <= addr) {
      addr += 0x1000;
      continue;
    }
    const bool exec =
        mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
        (mbi.Protect &
         (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
    if (exec) {
      uintptr_t scanStart = addr > regionBase ? addr : regionBase;
      uintptr_t scanEnd = regionEnd < end ? regionEnd : end;
      for (uintptr_t p = scanStart; p + 5 <= scanEnd && (int)out.size() < maxOut; p++) {
        const uint8_t *b = (const uint8_t *)p;
        if (b[0] != 0xE8)
          continue;
        int32_t rel = *(const int32_t *)(b + 1);
        uintptr_t dest = p + 5 + (intptr_t)rel;
        if (dest != target)
          continue;
        XrefHit x;
        x.call_site = p;
        x.target = dest;
        // 128 before, 64 after
        uintptr_t beforeStart = p > scanStart + 128 ? p - 128 : scanStart;
        size_t beforeN = (size_t)(p - beforeStart);
        x.before_hex = HexBytes((const uint8_t *)beforeStart, beforeN);
        size_t afterN = 64;
        if (p + 5 + afterN > scanEnd)
          afterN = (size_t)(scanEnd - (p + 5));
        x.after_hex = HexBytes(b + 5, afterN);
        // Other E8 targets in before window
        for (uintptr_t q = beforeStart; q + 5 <= p; q++) {
          const uint8_t *qb = (const uint8_t *)q;
          if (qb[0] != 0xE8)
            continue;
          int32_t r2 = *(const int32_t *)(qb + 1);
          uintptr_t d2 = q + 5 + (intptr_t)r2;
          if (d2 < base || d2 + 32 > end)
            continue;
          // only if d2 in executable image range
          std::string first32 = HexBytes((const uint8_t *)d2, 32);
          x.nearby_targets.push_back({d2, first32});
          if (x.nearby_targets.size() >= 12)
            break;
        }
        out.push_back(std::move(x));
      }
    }
    if (regionEnd <= addr)
      break;
    addr = regionEnd;
  }
  return out;
}

struct StrHit {
  std::string needle;
  uintptr_t addr = 0;
  uint32_t rva = 0;
};

std::vector<StrHit> FindStrings(uintptr_t base, size_t size, const char **needles, int nNeedles) {
  std::vector<StrHit> out;
  if (!base || !size)
    return out;
  const uintptr_t end = base + size;
  uintptr_t addr = base;
  while (addr < end) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)))
      break;
    uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
    uintptr_t regionEnd = regionBase + mbi.RegionSize;
    if (regionEnd <= addr) {
      addr += 0x1000;
      continue;
    }
    const bool readable =
        mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
    if (readable) {
      uintptr_t scanStart = addr > regionBase ? addr : regionBase;
      uintptr_t scanEnd = regionEnd < end ? regionEnd : end;
      size_t n = (size_t)(scanEnd - scanStart);
      const char *mem = (const char *)scanStart;
      for (int i = 0; i < nNeedles; i++) {
        size_t already = 0;
        for (const auto &h : out)
          if (h.needle == needles[i])
            already++;
        if ((int)already >= kMaxStringHits)
          continue;
        size_t len = strlen(needles[i]);
        if (len == 0 || n < len)
          continue;
        for (size_t off = 0; off + len <= n; off++) {
          if (memcmp(mem + off, needles[i], len) == 0) {
            StrHit h;
            h.needle = needles[i];
            h.addr = scanStart + off;
            h.rva = (uint32_t)(h.addr - base);
            out.push_back(h);
            break; // one hit per needle per region pass; still capped overall
          }
        }
      }
    }
    if (regionEnd <= addr)
      break;
    addr = regionEnd;
  }
  return out;
}

bool WriteAll(const char *path, const std::string &body) {
  FILE *f = nullptr;
  if (fopen_s(&f, path, "wb") != 0 || !f)
    return false;
  fwrite(body.data(), 1, body.size(), f);
  fclose(f);
  return true;
}

} // namespace

bool FingerprintModule(HMODULE hmod, ModuleFingerprint &out) {
  if (!hmod)
    hmod = GetModuleHandleA(nullptr);
  char path[MAX_PATH] = {};
  if (!GetModuleFileNameA(hmod, path, MAX_PATH))
    return false;
  out.path = path;
  const char *slash = strrchr(path, '\\');
  out.module = slash ? slash + 1 : path;
  out.base = (uintptr_t)hmod;

  struct LocalModInfo {
    LPVOID lpBaseOfDll;
    DWORD SizeOfImage;
    LPVOID EntryPoint;
  } mi{};
  typedef BOOL(WINAPI *GMI)(HANDLE, HMODULE, LocalModInfo *, DWORD);
  GMI gmi = (GMI)GetProcAddress(GetModuleHandleA("kernel32.dll"), "K32GetModuleInformation");
  if (!gmi) {
    HMODULE ps = LoadLibraryA("psapi.dll");
    if (ps)
      gmi = (GMI)GetProcAddress(ps, "GetModuleInformation");
  }
  if (gmi && gmi(GetCurrentProcess(), hmod, &mi, sizeof(mi))) {
    out.image_size = (size_t)mi.SizeOfImage;
  } else {
    out.image_size = 0;
  }

  if (out.image_size) {
    ReadPeHeaders((const uint8_t *)hmod, out.image_size, out.pe_timestamp, out.text_rva,
                  out.text_size);
  }
  out.file_version = FileVersionString(path);
  out.sha256 = Sha256File(path);
  return true;
}

bool RunLuaSignatureProbe(const HookConfig &cfg, const std::string & /*dllDir*/,
                          const ModuleFingerprint &fp, uintptr_t pcallAddr,
                          const std::string &outJsonPath, char *err, size_t errN) {
  auto fail = [&](const char *m) -> bool {
    if (err && errN)
      _snprintf_s(err, errN, _TRUNCATE, "%s", m);
    return false;
  };
  if (!fp.base || !fp.image_size)
    return fail("no module image");

  uintptr_t base = fp.base;
  size_t size = fp.image_size;

  // Prefer .text window if known
  uintptr_t scanBase = base;
  size_t scanSize = size;
  if (fp.text_rva && fp.text_size && fp.text_rva + fp.text_size <= size) {
    scanBase = base + fp.text_rva;
    scanSize = fp.text_size;
  }

  auto exactLoad = PatternScanAll(scanBase, scanSize, cfg.sig_lua_load.c_str());
  auto exactPcall = PatternScanAll(scanBase, scanSize, cfg.sig_lua_pcall.c_str());
  if (!pcallAddr && exactPcall.size() == 1)
    pcallAddr = exactPcall[0];

  auto fuzzy = FuzzyScan(scanBase, scanSize, cfg.sig_lua_load.c_str(), kMaxFuzzy);
  auto xrefs = pcallAddr ? FindDirectCallXrefs(scanBase, scanSize, pcallAddr, kMaxXrefs)
                         : std::vector<XrefHit>{};

  const char *needles[] = {
      "attempt to load a binary chunk",
      "cannot resume dead coroutine",
      "stack overflow",
      "=(load)",
      "syntax error",
      "not enough memory",
      "attempt to call a",
      "bad argument",
  };
  auto strs = FindStrings(base, size, needles, (int)(sizeof(needles) / sizeof(needles[0])));

  JsonBuf j;
  j.append("{\n");
  j.append("  \"schema_version\":1,\n");
  j.append("  \"diagnostic_only\":true,\n");
  j.append("  \"never_hooks_fuzzy\":true,\n");
  j.append("  \"module\":\"");
  j.append(JsonEsc(fp.module));
  j.append("\",\n  \"path\":\"");
  j.append(JsonEsc(fp.path));
  j.append("\",\n  \"image_size\":");
  j.append(std::to_string(fp.image_size));
  j.append(",\n  \"pe_timestamp\":");
  j.append(std::to_string(fp.pe_timestamp));
  j.append(",\n  \"text_rva\":\"");
  j.append(HexU64(fp.text_rva));
  j.append("\",\n  \"text_size\":");
  j.append(std::to_string(fp.text_size));
  j.append(",\n  \"file_version\":\"");
  j.append(JsonEsc(fp.file_version));
  j.append("\",\n  \"sha256\":\"");
  j.append(JsonEsc(fp.sha256));
  j.append("\",\n  \"base\":\"");
  j.append(HexU64(base));
  j.append("\",\n");

  j.append("  \"exact_scan\":{\n");
  j.append("    \"lua_load\":{\"pattern\":\"legacy\",\"matches\":");
  j.append(std::to_string(exactLoad.size()));
  j.append("},\n");
  j.append("    \"lua_pcallk\":{\"matches\":");
  j.append(std::to_string(exactPcall.size()));
  if (pcallAddr) {
    j.append(",\"address\":\"");
    j.append(HexU64(pcallAddr));
    j.append("\",\"rva\":\"");
    j.append(HexU64(pcallAddr - base));
    j.append("\"");
  }
  j.append("}\n  },\n");

  j.append("  \"fuzzy_lua_load\":[\n");
  for (size_t i = 0; i < fuzzy.size(); i++) {
    const auto &h = fuzzy[i];
    j.append("    {\"address\":\"");
    j.append(HexU64(h.addr));
    j.append("\",\"rva\":\"");
    j.append(HexU64(h.addr - base));
    j.append("\",\"mismatches\":");
    j.append(std::to_string(h.mismatches));
    j.append(",\"compared\":");
    j.append(std::to_string(h.compared));
    j.append(",\"hex\":\"");
    j.append(h.hex64);
    j.append("\"}");
    if (i + 1 < fuzzy.size())
      j.append(",");
    j.append("\n");
  }
  j.append("  ],\n");

  j.append("  \"pcall_xrefs\":[\n");
  for (size_t i = 0; i < xrefs.size(); i++) {
    const auto &x = xrefs[i];
    j.append("    {\"call_site\":\"");
    j.append(HexU64(x.call_site));
    j.append("\",\"call_rva\":\"");
    j.append(HexU64(x.call_site - base));
    j.append("\",\"before_hex\":\"");
    j.append(x.before_hex);
    j.append("\",\"after_hex\":\"");
    j.append(x.after_hex);
    j.append("\",\"nearby_call_targets\":[");
    for (size_t k = 0; k < x.nearby_targets.size(); k++) {
      j.append("{\"address\":\"");
      j.append(HexU64(x.nearby_targets[k].first));
      j.append("\",\"rva\":\"");
      j.append(HexU64(x.nearby_targets[k].first - base));
      j.append("\",\"first32\":\"");
      j.append(x.nearby_targets[k].second);
      j.append("\"}");
      if (k + 1 < x.nearby_targets.size())
        j.append(",");
    }
    j.append("]}");
    if (i + 1 < xrefs.size())
      j.append(",");
    j.append("\n");
  }
  j.append("  ],\n");

  j.append("  \"string_anchors\":[\n");
  for (size_t i = 0; i < strs.size(); i++) {
    j.append("    {\"string\":\"");
    j.append(JsonEsc(strs[i].needle));
    j.append("\",\"address\":\"");
    j.append(HexU64(strs[i].addr));
    j.append("\",\"rva\":\"");
    j.append(HexU64(strs[i].rva));
    j.append("\"}");
    if (i + 1 < strs.size())
      j.append(",");
    j.append("\n");
  }
  j.append("  ],\n");

  j.append("  \"note\":\"Fuzzy candidates must NEVER be used for hooks.\"\n");
  j.append("}\n");

  if (!WriteAll(outJsonPath.c_str(), j.s))
    return fail("write probe json failed");
  if (err && errN)
    _snprintf_s(err, errN, _TRUNCATE, "ok bytes=%zu truncated=%d", j.s.size(),
                j.truncated ? 1 : 0);
  return true;
}

bool RunLuaSignatureProbeFile(const char *modulePath, const HookConfig &cfg,
                              const std::string &outJsonPath, char *err, size_t errN) {
  auto fail = [&](const char *m) -> bool {
    if (err && errN)
      _snprintf_s(err, errN, _TRUNCATE, "%s", m);
    return false;
  };
  HANDLE h = CreateFileA(modulePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return fail("open module failed");
  DWORD sz = GetFileSize(h, nullptr);
  if (sz == INVALID_FILE_SIZE || sz < 0x400) {
    CloseHandle(h);
    return fail("bad size");
  }
  // Map file for PE parse + section scan (file offsets, not VA). Cap read of .text only.
  HANDLE map = CreateFileMappingA(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (!map) {
    CloseHandle(h);
    return fail("map failed");
  }
  const uint8_t *view = (const uint8_t *)MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
  if (!view) {
    CloseHandle(map);
    CloseHandle(h);
    return fail("view failed");
  }

  ModuleFingerprint fp;
  fp.path = modulePath;
  const char *sl = strrchr(modulePath, '\\');
  fp.module = sl ? sl + 1 : modulePath;
  fp.image_size = sz;
  fp.sha256 = Sha256File(modulePath);
  fp.file_version = FileVersionString(modulePath);
  ReadPeHeaders(view, sz, fp.pe_timestamp, fp.text_rva, fp.text_size);

  // Offline: scan raw file bytes of .text using file pointer = PointerToRawData.
  // For simplicity scan whole mapped file with VirtualQuery-less path: PatternScanAll needs
  // VirtualQuery — use a private committed buffer copy of .text instead.
  uint32_t textRaw = 0, textRawSz = 0;
  {
    uint32_t lfanew = *(const uint32_t *)(view + 0x3C);
    const uint8_t *nt = view + lfanew;
    uint16_t numSec = *(const uint16_t *)(nt + 6);
    uint16_t optSize = *(const uint16_t *)(nt + 20);
    const uint8_t *sec = nt + 24 + optSize;
    for (uint16_t i = 0; i < numSec; i++) {
      const uint8_t *s = sec + i * 40;
      char name[9] = {};
      memcpy(name, s, 8);
      if (strcmp(name, ".text") == 0) {
        textRawSz = *(const uint32_t *)(s + 16);
        textRaw = *(const uint32_t *)(s + 20);
        break;
      }
    }
  }

  // Build a fake "image" buffer: allocate RW and copy .text so VirtualQuery sees committed pages.
  size_t copyN = textRaw && textRawSz && textRaw + textRawSz <= sz ? textRawSz : (sz > 64 * 1024 * 1024 ? 64 * 1024 * 1024 : sz);
  size_t copyOff = textRaw && textRawSz ? textRaw : 0;
  uint8_t *buf = (uint8_t *)VirtualAlloc(nullptr, copyN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!buf) {
    UnmapViewOfFile(view);
    CloseHandle(map);
    CloseHandle(h);
    return fail("VirtualAlloc failed");
  }
  memcpy(buf, view + copyOff, copyN);
  DWORD oldProt = 0;
  VirtualProtect(buf, copyN, PAGE_EXECUTE_READ, &oldProt);

  fp.base = (uintptr_t)buf;
  fp.image_size = copyN;
  // RVAs in output will be relative to this buffer start (= .text rva if sliced).
  uintptr_t pcall = 0;
  auto pcallHits = PatternScanAll((uintptr_t)buf, copyN, cfg.sig_lua_pcall.c_str());
  if (pcallHits.size() == 1)
    pcall = pcallHits[0];

  bool ok = RunLuaSignatureProbe(cfg, "", fp, pcall, outJsonPath, err, errN);

  VirtualFree(buf, 0, MEM_RELEASE);
  UnmapViewOfFile(view);
  CloseHandle(map);
  CloseHandle(h);
  return ok;
}

} // namespace face_capture
