#pragma once

#include <cstdint>
#include <cstring>
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

inline std::string_view status_line(int status) noexcept {
    switch (status) {
        case 200: return "HTTP/1.1 200 OK\r\n";
        case 201: return "HTTP/1.1 201 Created\r\n";
        case 202: return "HTTP/1.1 202 Accepted\r\n";
        case 204: return "HTTP/1.1 204 No Content\r\n";
        case 400: return "HTTP/1.1 400 Bad Request\r\n";
        case 401: return "HTTP/1.1 401 Unauthorized\r\n";
        case 403: return "HTTP/1.1 403 Forbidden\r\n";
        case 404: return "HTTP/1.1 404 Not Found\r\n";
        case 405: return "HTTP/1.1 405 Method Not Allowed\r\n";
        case 409: return "HTTP/1.1 409 Conflict\r\n";
        case 422: return "HTTP/1.1 422 Unprocessable Entity\r\n";
        case 500: return "HTTP/1.1 500 Internal Server Error\r\n";
        default: return "HTTP/1.1 200 OK\r\n";
    }
}

inline void append_u64_dec(std::string& out, uint64_t v) {
    char tmp[24];
    char* p = tmp + sizeof(tmp);
    do {
        *--p = static_cast<char>('0' + (v % 10));
        v /= 10;
    } while (v != 0);
    out.append(p, static_cast<size_t>((tmp + sizeof(tmp)) - p));
}

inline void append_u64_hex(std::string& out, uint64_t v) {
    static constexpr char kHex[] = "0123456789abcdef";
    char tmp[16];
    char* p = tmp + sizeof(tmp);
    do {
        *--p = kHex[v & 0xfu];
        v >>= 4;
    } while (v != 0);
    out.append(p, static_cast<size_t>((tmp + sizeof(tmp)) - p));
}

inline void build_http_response(
    HttpResponse& out,
    int status,
    std::string_view content_type,
    std::string_view body,
    uint64_t req_id,
    bool keep_alive,
    std::string_view extra_headers = "") {
    out.raw_ptr = nullptr;
    out.raw_len = 0;
    out.owned_raw.clear();
    out.owned_raw.reserve(128 + content_type.size() + extra_headers.size() + body.size());
    out.owned_raw.append(status_line(status));
    out.owned_raw.append("Content-Type: ", 14);
    out.owned_raw.append(content_type);
    out.owned_raw.append("\r\nX-GitHub-Request-Id: ", 23);
    append_u64_hex(out.owned_raw, req_id ? req_id : 1u);
    if (!keep_alive) {
        out.owned_raw.append("\r\nConnection: close", 19);
    }
    out.owned_raw.append("\r\nContent-Length: ", 18);
    append_u64_dec(out.owned_raw, body.size());
    out.owned_raw.append("\r\n", 2);
    if (!extra_headers.empty()) out.owned_raw.append(extra_headers);
    out.owned_raw.append("\r\n", 2);
    out.owned_raw.append(body);
}

inline void build_git_http_response(
    HttpResponse& out,
    std::string_view content_type,
    std::string_view body,
    bool keep_alive) {
    out.raw_ptr = nullptr;
    out.raw_len = 0;
    out.owned_raw.clear();
    out.owned_raw.reserve(96 + content_type.size() + body.size());
    out.owned_raw.append("HTTP/1.1 200 OK\r\nContent-Type: ", 31);
    out.owned_raw.append(content_type);
    if (!keep_alive) {
        out.owned_raw.append("\r\nConnection: close", 19);
    }
    out.owned_raw.append("\r\nContent-Length: ", 18);
    append_u64_dec(out.owned_raw, body.size());
    out.owned_raw.append("\r\n\r\n", 4);
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
    std::string body;
    body.reserve(16 + message.size());
    body.append("{\"message\":\"", 12);
    for (char c : message) {
        if (c == '"' || c == '\\') body.push_back('\\');
        body.push_back(c);
    }
    body.append("\"}", 2);
    build_json_response(out, status, body, req_id, keep_alive);
}

} // namespace forge
