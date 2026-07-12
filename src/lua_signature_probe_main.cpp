/*
 * Offline diagnostic: LuaSignatureProbe.exe --module path\to\wwm.exe
 * Never hooks. Writes captures/lua_signature_probe.json next to cwd or --out.
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdio>
#include <string>

#include "hook/config.h"
#include "hook/lua_signature_probe.h"

using namespace face_capture;

static void Usage() {
  printf("Usage: LuaSignatureProbe.exe --module <path-to-wwm.exe> [--out file.json]\n");
  printf("Read-only PE probe. Does not inject or patch.\n");
}

int main(int argc, char **argv) {
  const char *mod = nullptr;
  const char *out = "lua_signature_probe.json";
  for (int i = 1; i < argc; i++) {
    if ((!strcmp(argv[i], "--module") || !strcmp(argv[i], "-m")) && i + 1 < argc)
      mod = argv[++i];
    else if ((!strcmp(argv[i], "--out") || !strcmp(argv[i], "-o")) && i + 1 < argc)
      out = argv[++i];
    else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      Usage();
      return 0;
    }
  }
  if (!mod) {
    Usage();
    return 2;
  }

  HookConfig cfg; // defaults / legacy patterns
  char err[256] = {};
  printf("[*] Probing %s\n", mod);
  if (!RunLuaSignatureProbeFile(mod, cfg, out, err, sizeof(err))) {
    printf("[!] Probe failed: %s\n", err);
    return 1;
  }
  printf("[+] Wrote %s (%s)\n", out, err);
  printf("    Fuzzy candidates are diagnostic only — never used for hooks.\n");
  return 0;
}
