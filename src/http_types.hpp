#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace forge {

struct HttpRequest {
    std::string_view method;
    std::string_view target;
    std::string_view path;
    std::string_view query;
    std::string_view host;
    std::string_view authorization;
    std::string_view content_type;
    std::string_view git_protocol;
    std::string_view mcp_session_id;
    std::string_view mcp_protocol_version;
    bool keep_alive = true;
    std::string_view body;
};

struct HttpResponse {
    // If non-null, send this exact prebuilt HTTP/1.1 buffer (zero-copy fast path!)
    const char* raw_ptr = nullptr;
    size_t raw_len = 0;
    // Otherwise send owned_raw (built by helpers below)
    std::string owned_raw;

    void set_prebuilt(const std::string& buf) noexcept {
        raw_ptr = buf.data();
        raw_len = buf.size();
    }
};

inline const char* status_reason(int status) noexcept {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 422: return "Unprocessable Entity";
        case 500: return "Internal Server Error";
        default: return "OK";
    }
}

inline void build_http_response(
    HttpResponse& out,
    int status,
    std::string_view content_type,
    std::string_view body,
    uint64_t req_id,
    bool keep_alive,
    std::string_view extra_headers = "") {
    char hdr[512];
    int n = keep_alive
        ? std::snprintf(
            hdr, sizeof(hdr),
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %.*s\r\n"
            "X-GitHub-Request-Id: %08llx\r\n"
            "Content-Length: %zu\r\n",
            status, status_reason(status),
            static_cast<int>(content_type.size()), content_type.data(),
            static_cast<unsigned long long>(req_id & 0xffffffffull),
            body.size())
        : std::snprintf(
            hdr, sizeof(hdr),
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %.*s\r\n"
            "X-GitHub-Request-Id: %08llx\r\n"
            "Connection: close\r\n"
            "Content-Length: %zu\r\n",
            status, status_reason(status),
            static_cast<int>(content_type.size()), content_type.data(),
            static_cast<unsigned long long>(req_id & 0xffffffffull),
            body.size());
    out.raw_ptr = nullptr;
    out.raw_len = 0;
    out.owned_raw.clear();
    out.owned_raw.reserve(static_cast<size_t>(n) + extra_headers.size() + 2 + body.size());
    out.owned_raw.append(hdr, static_cast<size_t>(n));
    if (!extra_headers.empty()) out.owned_raw.append(extra_headers);
    out.owned_raw.append("\r\n");
    out.owned_raw.append(body);
}

inline void build_json_response(
    HttpResponse& out,
    int status,
    std::string_view json_body,
    uint64_t req_id,
    bool keep_alive,
    std::string_view extra_headers = "") {
    build_http_response(out, status, "application/json", json_body, req_id, keep_alive, extra_headers);
}

inline void build_error_json(
    HttpResponse& out,
    int status,
    std::string_view message,
    uint64_t req_id,
    bool keep_alive) {
    std::string body = "{\"message\":\"";
    for (char c : message) {
        if (c == '"' || c == '\\') body.push_back('\\');
        body.push_back(c);
    }
    body += "\"}";
    build_json_response(out, status, body, req_id, keep_alive);
}

} // namespace forge
