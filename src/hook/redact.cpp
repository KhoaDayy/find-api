#include "hook/redact.h"
#include "hook/capture_writer.h"
#include "hook/sha256.h"
#include <Windows.h>
#include <cctype>
#include <cstring>
#include <cstdio>

namespace face_capture {
namespace {

bool StartsWithCI(const std::string &s, const char *p) {
  size_t n = strlen(p);
  if (s.size() < n)
    return false;
  for (size_t i = 0; i < n; i++)
    if (tolower((unsigned char)s[i]) != tolower((unsigned char)p[i]))
      return false;
  return true;
}

bool ContainsCI(const std::string &s, const char *p) {
  std::string a = s, b = p;
  for (auto &c : a)
    c = (char)tolower((unsigned char)c);
  for (auto &c : b)
    c = (char)tolower((unsigned char)c);
  return a.find(b) != std::string::npos;
}

bool LooksLikeFaceData(const std::string &s) {
  if (s.size() < 4)
    return false;
  if ((s[0] == 'R' || s[0] == 'r' || s[0] == 'D' || s[0] == 'd') && s[1] == '6' &&
      s[2] == '7')
    return true;
  if (s.find("|*|") != std::string::npos && s.size() > 40)
    return true;
  return false;
}

bool IsPrintableText(const uint8_t *p, size_t n) {
  size_t check = n < 64 ? n : 64;
  int bad = 0;
  for (size_t i = 0; i < check; i++) {
    if (p[i] == 0)
      bad++;
    else if (p[i] < 9 || (p[i] > 13 && p[i] < 32))
      bad++;
  }
  return bad < 3;
}

} // namespace

bool IsSecretHeaderName(const std::string &name) {
  static const char *keys[] = {"authorization", "cookie",      "set-cookie",
                               "x-auth",        "x-auth-token", "token",
                               "server_token",  "server-token", "h72-ms-uid",
                               "proxy-authorization"};
  std::string n = name;
  for (auto &c : n)
    c = (char)tolower((unsigned char)c);
  for (auto *k : keys)
    if (n == k || n.find(k) != std::string::npos)
      return true;
  return false;
}

std::string RedactHeaderValue(const std::string &name, const std::string &value,
                              bool computeHash) {
  if (!IsSecretHeaderName(name) && value.find("_face_123_face_") == std::string::npos &&
      value.find("session=") == std::string::npos) {
    if (value.size() > 256)
      return value.substr(0, 64) + "...(len=" + std::to_string(value.size()) + ")";
    return value;
  }
  std::string out = "***";
  if (computeHash && !value.empty())
    out += "|sha256:" + sha256_hex(value);
  out += "|len=" + std::to_string(value.size());
  if (value.find("_face_123_face_") == 0)
    out = std::string("_face_123_face_***|len=") + std::to_string(value.size());
  return out;
}

std::string SummarizeBodyJson(const void *data, size_t len, bool captureFullFaceData) {
  if (!data || len == 0)
    return "{\"body_length\":0,\"body_kind\":\"empty\"}";

  const uint8_t *p = (const uint8_t *)data;
  std::string text;
  bool printable = IsPrintableText(p, len);
  if (printable) {
    text.assign((const char *)p, len);
    // strip trailing NULs
    while (!text.empty() && text.back() == '\0')
      text.pop_back();
  }

  std::string hash = sha256_hex(data, len);
  std::string kind = printable ? "text" : "binary";

  if (printable) {
    std::string trim = text;
    while (!trim.empty() && (trim[0] == ' ' || trim[0] == '\n' || trim[0] == '\r'))
      trim.erase(trim.begin());
    if (!trim.empty() && (trim[0] == '{' || trim[0] == '[')) {
      kind = "json";
      // Extract face_data length/hash without storing full payload
      size_t fd = text.find("\"face_data\"");
      std::string faceHash;
      size_t faceLen = 0;
      if (fd != std::string::npos) {
        size_t colon = text.find(':', fd);
        size_t q1 = text.find('"', colon + 1);
        if (q1 != std::string::npos) {
          size_t q2 = text.find('"', q1 + 1);
          // face_data is long — may contain escaped chars; find end carefully
          // For capture we hash the whole body and note face_data presence
          faceLen = (q2 != std::string::npos && q2 > q1) ? (q2 - q1 - 1) : 0;
          // Better: find value start and scan for unescaped "
          if (q1 != std::string::npos) {
            size_t i = q1 + 1;
            while (i < text.size()) {
              if (text[i] == '\\') {
                i += 2;
                continue;
              }
              if (text[i] == '"')
                break;
              i++;
            }
            if (i > q1 + 1) {
              std::string fdVal = text.substr(q1 + 1, i - q1 - 1);
              faceLen = fdVal.size();
              faceHash = sha256_hex(fdVal);
              if (!captureFullFaceData) {
                // rebuild minimal JSON summary without embedding face_data
              }
            }
          }
        }
      }
      // keys list (top-level rough)
      std::string keys = "[";
      bool first = true;
      size_t pos = 0;
      while ((pos = text.find('"', pos)) != std::string::npos) {
        size_t e = text.find('"', pos + 1);
        if (e == std::string::npos)
          break;
        // crude: only top-level keys after { or ,
        if (pos > 0 && (text[pos - 1] == '{' || text[pos - 1] == ',' ||
                        text[pos - 1] == ' ' || text[pos - 1] == '\n')) {
          std::string k = text.substr(pos + 1, e - pos - 1);
          if (k.find(':') == std::string::npos && k.size() < 40 &&
              k.find(' ') == std::string::npos) {
            // check next non-space is :
            size_t c = text.find_first_not_of(" \t\r\n", e + 1);
            if (c != std::string::npos && text[c] == ':') {
              if (!first)
                keys += ",";
              keys += JsonString(k);
              first = false;
            }
          }
        }
        pos = e + 1;
        if (keys.size() > 500)
          break;
      }
      keys += "]";

      std::string out = "{";
      out += "\"body_kind\":\"json\",";
      out += "\"body_length\":" + std::to_string(len) + ",";
      out += "\"body_sha256\":" + JsonString(hash) + ",";
      out += "\"top_level_keys\":" + keys;
      if (!faceHash.empty()) {
        out += ",\"face_data\":{\"__face_data__\":true,\"length\":" +
               std::to_string(faceLen) + ",\"sha256\":" + JsonString(faceHash) + "}";
      }
      // preserve identity fields if short
      auto grab = [&](const char *key) -> std::string {
        std::string pat = std::string("\"") + key + "\"";
        size_t p = text.find(pat);
        if (p == std::string::npos)
          return {};
        p = text.find(':', p);
        if (p == std::string::npos)
          return {};
        p = text.find_first_not_of(" \t\r\n", p + 1);
        if (p == std::string::npos)
          return {};
        if (text[p] == '"') {
          size_t e = text.find('"', p + 1);
          if (e == std::string::npos)
            return {};
          std::string v = text.substr(p + 1, e - p - 1);
          if (LooksLikeFaceData(v))
            return {};
          return v;
        }
        // number
        size_t e = p;
        while (e < text.size() &&
               (isdigit((unsigned char)text[e]) || text[e] == '-' || text[e] == '.'))
          e++;
        return text.substr(p, e - p);
      };
      std::string pid = grab("pid");
      std::string hostnum = grab("hostnum");
      std::string fst = grab("face_share_type");
      if (!pid.empty())
        out += ",\"pid\":" + JsonString(pid);
      if (!hostnum.empty())
        out += ",\"hostnum\":" + hostnum;
      if (!fst.empty())
        out += ",\"face_share_type\":" + fst;
      out += ",\"has_dressing\":" +
             std::string(text.find("\"dressing\"") != std::string::npos ? "true" : "false");
      out += "}";
      return out;
    }
    if (LooksLikeFaceData(text)) {
      return std::string("{\"body_kind\":\"raw_face_data\",\"body_length\":") +
             std::to_string(len) + ",\"body_sha256\":" + JsonString(hash) +
             ",\"prefix\":" + JsonString(text.substr(0, 3)) +
             ",\"face_data\":{\"__face_data__\":true,\"length\":" + std::to_string(len) +
             ",\"sha256\":" + JsonString(hash) + "}}";
    }
    if (text.find("--") == 0 || ContainsCI(std::string((const char *)p, len < 64 ? len : 64),
                                           "multipart")) {
      return std::string("{\"body_kind\":\"multipart\",\"body_length\":") +
             std::to_string(len) + ",\"body_sha256\":" + JsonString(hash) +
             ",\"note\":\"fields not dumped\"}";
    }
  }

  // binary / msgpack
  char hex[48] = {0};
  int pos = 0;
  for (size_t i = 0; i < 16 && i < len; i++)
    pos += sprintf(hex + pos, "%02x", p[i]);
  return std::string("{\"body_kind\":\"binary\",\"body_length\":") + std::to_string(len) +
         ",\"body_sha256\":" + JsonString(hash) + ",\"first16_hex\":" + JsonString(hex) +
         "}";
}

bool IsFilePickerHost(const std::string &host) {
  static const char *hosts[] = {
      "fp.ps.netease.com",
      "fp.ps.easebar.com",
      "h72face-cn.fp.ps.netease.com",
      "h72.fp.ps.netease.com",
      "h72wxj.fp.ps.netease.com",
      "h72sg.fp.ps.easebar.com",
  };
  for (auto *h : hosts)
    if (_stricmp(host.c_str(), h) == 0)
      return true;
  // also any *.fp.ps.*
  if (ContainsCI(host, "fp.ps.netease.com") || ContainsCI(host, "fp.ps.easebar.com"))
    return true;
  return false;
}

bool IsFilePickerPath(const std::string &path) {
  return ContainsCI(path, "/h72face") || ContainsCI(path, "/file/new") ||
         ContainsCI(path, "/file/");
}

bool ShouldCaptureRequest(const std::string &host, const std::string &path,
                          bool captureOnlyFilepicker) {
  if (!captureOnlyFilepicker)
    return true;
  if (IsFilePickerHost(host))
    return true;
  if (IsFilePickerPath(path) && ContainsCI(path, "face"))
    return true;
  if (ContainsCI(path, "/h72face") || ContainsCI(path, "/h72facesg"))
    return true;
  return false;
}

std::string ParseObjectKeyFromUrl(const std::string &url) {
  size_t p = url.rfind("/file/");
  if (p == std::string::npos)
    return {};
  std::string key = url.substr(p + 6);
  size_t q = key.find_first_of("?#");
  if (q != std::string::npos)
    key = key.substr(0, q);
  return key;
}

std::string WideToUtf8(const wchar_t *w, size_t nchars) {
  if (!w)
    return {};
  if (nchars == (size_t)-1)
    nchars = wcslen(w);
  if (nchars == 0)
    return {};
  int need = WideCharToMultiByte(CP_UTF8, 0, w, (int)nchars, nullptr, 0, nullptr, nullptr);
  if (need <= 0)
    return {};
  std::string out(need, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w, (int)nchars, &out[0], need, nullptr, nullptr);
  return out;
}

} // namespace face_capture
