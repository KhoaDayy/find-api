#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <cstdint>

struct PatternByte {
    uint8_t value;
    bool    wildcard;
};

static std::vector<PatternByte> ParsePattern(const char* pattern) {
    std::vector<PatternByte> bytes;
    std::istringstream iss(pattern);
    std::string token;
    while (iss >> token) {
        if (token == "?" || token == "??") {
            bytes.push_back({ 0, true });
        } else {
            bytes.push_back({ (uint8_t)strtoul(token.c_str(), nullptr, 16), false });
        }
    }
    return bytes;
}

static std::vector<uintptr_t> PatternScanAll(uintptr_t base, size_t size, const char* pattern) {
    auto bytes = ParsePattern(pattern);
    std::vector<uintptr_t> results;
    if (bytes.empty()) return results;

    const size_t patLen = bytes.size();

    for (size_t i = 0; i <= size - patLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patLen; j++) {
            if (!bytes[j].wildcard &&
                *(uint8_t*)(base + i + j) != bytes[j].value) {
                found = false;
                break;
            }
        }
        if (found) {
            results.push_back(base + i);
        }
    }
    return results;
}

static uintptr_t PatternScan(uintptr_t base, size_t size, const char* pattern) {
    auto results = PatternScanAll(base, size, pattern);
    return results.empty() ? 0 : results[0];
}
