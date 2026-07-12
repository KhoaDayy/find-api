#pragma once
#include <Windows.h>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

struct PatternByte {
  uint8_t value;
  bool wildcard;
};

static std::vector<PatternByte> ParsePattern(const char *pattern) {
  std::vector<PatternByte> bytes;
  std::istringstream iss(pattern);
  std::string token;
  while (iss >> token) {
    if (token == "?" || token == "??") {
      bytes.push_back({0, true});
    } else {
      bytes.push_back({(uint8_t)strtoul(token.c_str(), nullptr, 16), false});
    }
  }
  return bytes;
}

// Scan only committed readable pages. Raw image SizeOfImage includes
// uncommitted gaps — reading those AVs and can take the game down.
static std::vector<uintptr_t> PatternScanAll(uintptr_t base, size_t size,
                                             const char *pattern) {
  std::vector<uintptr_t> results;
  auto bytes = ParsePattern(pattern);
  if (bytes.empty() || !base || !size)
    return results;

  const size_t patLen = bytes.size();
  if (size < patLen)
    return results;

  const uintptr_t end = base + size;
  uintptr_t addr = base;
  while (addr + patLen <= end) {
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
        mbi.State == MEM_COMMIT &&
        !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
        (mbi.Protect &
         (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE |
          PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));

    if (readable) {
      uintptr_t scanStart = addr > regionBase ? addr : regionBase;
      uintptr_t scanEnd = regionEnd < end ? regionEnd : end;
      if (scanEnd >= scanStart + patLen) {
        const uint8_t *p = (const uint8_t *)scanStart;
        const size_t n = (size_t)(scanEnd - scanStart - patLen);
        for (size_t i = 0; i <= n; i++) {
          bool found = true;
          for (size_t j = 0; j < patLen; j++) {
            if (!bytes[j].wildcard && p[i + j] != bytes[j].value) {
              found = false;
              break;
            }
          }
          if (found)
            results.push_back(scanStart + i);
        }
      }
    }

    if (regionEnd <= addr)
      break;
    addr = regionEnd;
  }
  return results;
}

static uintptr_t PatternScan(uintptr_t base, size_t size, const char *pattern) {
  auto results = PatternScanAll(base, size, pattern);
  return results.empty() ? 0 : results[0];
}
