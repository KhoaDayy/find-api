#include "hook/capture_writer.h"
#include <Windows.h>
#include <cstdio>
#include <mutex>
#include <sys/stat.h>

namespace face_capture {
namespace {
std::mutex g_mu;
std::string g_path;
FILE *g_file = nullptr;

void EnsureDirForFile(const std::string &path) {
  size_t pos = path.find_last_of("\\/");
  if (pos == std::string::npos)
    return;
  std::string dir = path.substr(0, pos);
  // create nested dirs simply
  for (size_t i = 0; i < dir.size(); i++) {
    if (dir[i] == '\\' || dir[i] == '/') {
      std::string part = dir.substr(0, i);
      if (!part.empty())
        CreateDirectoryA(part.c_str(), nullptr);
    }
  }
  CreateDirectoryA(dir.c_str(), nullptr);
}
} // namespace

std::string EscapeJson(const std::string &s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
    case '"':
      o += "\\\"";
      break;
    case '\\':
      o += "\\\\";
      break;
    case '\n':
      o += "\\n";
      break;
    case '\r':
      o += "\\r";
      break;
    case '\t':
      o += "\\t";
      break;
    default:
      if (c < 0x20) {
        char buf[8];
        sprintf(buf, "\\u%04x", c);
        o += buf;
      } else
        o += (char)c;
    }
  }
  return o;
}

std::string JsonString(const std::string &s) {
  return "\"" + EscapeJson(s) + "\"";
}
std::string JsonNumber(long long n) { return std::to_string(n); }
std::string JsonBool(bool b) { return b ? "true" : "false"; }

void InitCaptureWriter(const std::string &outputPath) {
  std::lock_guard<std::mutex> lock(g_mu);
  g_path = outputPath;
  EnsureDirForFile(g_path);
  g_file = fopen(g_path.c_str(), "ab");
  if (g_file) {
    // schema marker
    fputs("{\"schema_version\":1,\"event\":\"capture_writer_open\",\"source\":\"native\"}\n",
          g_file);
    fflush(g_file);
  }
}

void WriteCaptureEvent(const std::string &source, const std::string &event,
                       const std::string &dataJson, const std::string &shareId,
                       const std::string &region) {
  std::lock_guard<std::mutex> lock(g_mu);
  if (!g_file)
    return;
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  ULARGE_INTEGER uli;
  uli.LowPart = ft.dwLowDateTime;
  uli.HighPart = ft.dwHighDateTime;
  // Windows epoch to unix ms approx
  long long ms = (long long)((uli.QuadPart - 116444736000000000ULL) / 10000ULL);

  fprintf(g_file,
          "{\"schema_version\":1,\"timestamp_ms\":%lld,\"source\":%s,\"event\":%s,"
          "\"share_id\":%s,\"thread_id\":%lu,\"region\":%s,\"data\":%s}\n",
          ms, JsonString(source).c_str(), JsonString(event).c_str(),
          JsonString(shareId).c_str(), GetCurrentThreadId(),
          JsonString(region).c_str(), dataJson.empty() ? "{}" : dataJson.c_str());
  fflush(g_file);
}

void ShutdownCaptureWriter() {
  std::lock_guard<std::mutex> lock(g_mu);
  if (g_file) {
    fclose(g_file);
    g_file = nullptr;
  }
}

} // namespace face_capture
