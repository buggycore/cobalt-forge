#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string>
#include <string_view>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

#include "git_http.hpp"
#include "graphql.hpp"
#include "http_types.hpp"
#include "mcp.hpp"
#include "rest.hpp"
#include "store.hpp"

namespace {

volatile sig_atomic_t g_stop = 0;

void on_signal(int) noexcept {
    g_stop = 1;
}

inline bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        unsigned char ca = static_cast<unsigned char>(a[i]);
        unsigned char cb = static_cast<unsigned char>(b[i]);
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
    }
    return true;
}

inline std::string_view trim_ows(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}

// Raw IPv4 HTTP/1.1 client for --env-mode (/register and idle-only /done). Zero glibc NSS DNS calls.
bool env_http_exchange(
    const char* ip, uint16_t port, const std::string& req_bytes, int& out_status, std::string& out_body) {
    out_status = 0;
    out_body.clear();
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;

    timeval tv{};
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return false;
    }
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return false;
    }

    size_t sent = 0;
    while (sent < req_bytes.size()) {
        ssize_t n = send(fd, req_bytes.data() + sent, req_bytes.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            close(fd);
            return false;
        }
        sent += static_cast<size_t>(n);
    }

    std::string resp;
    char buf[4096];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n > 0) {
            resp.append(buf, static_cast<size_t>(n));
            if (resp.size() > 65536) break;
        } else {
            break;
        }
    }
    close(fd);

    size_t sp1 = resp.find(' ');
    if (sp1 == std::string::npos || sp1 + 4 > resp.size()) return false;
    out_status = std::atoi(resp.c_str() + sp1 + 1);
    size_t hdr_end = resp.find("\r\n\r\n");
    if (hdr_end != std::string::npos) {
        out_body = resp.substr(hdr_end + 4);
    }
    return out_status > 0;
}

bool register_with_env(
    const char* ip, uint16_t env_port, const char* host_hdr, const char* prefix, uint16_t forge_port) {
    std::string body = "{\"port\":" + std::to_string(forge_port) + "}";
    std::string req =
        "POST " + std::string(prefix) + "/register HTTP/1.1\r\n"
        "Host: " + std::string(host_hdr) + "\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;

    int delay_ms = 50;
    for (int attempt = 0; attempt < 60 && !g_stop; ++attempt) {
        int status = 0;
        std::string resp_body;
        if (env_http_exchange(ip, env_port, req, status, resp_body)) {
            if (status == 200 || status == 409) return true;
            if (status == 400 || status == 405) return false;
        }
        usleep(static_cast<useconds_t>(delay_ms) * 1000u);
        if (delay_ms < 1000) delay_ms *= 2;
    }
    return false;
}

bool poll_env_done(const char* ip, uint16_t env_port, const std::string& done_req) {
    int status = 0;
    std::string resp_body;
    if (!env_http_exchange(ip, env_port, done_req, status, resp_body)) return false;
    if (status != 200) return false;
    return resp_body.find("\"done\":true") != std::string::npos ||
           resp_body.find("\"done\": true") != std::string::npos;
}

struct Conn {
    int fd = -1;
    bool active = false;
    std::string rbuf;
    size_t rpos = 0;
    std::string wbuf;
    size_t wpos = 0;
    bool close_after_write = false;
    bool epoll_out = false;

    void reset() noexcept {
        fd = -1;
        active = false;
        rbuf.clear();
        rpos = 0;
        wbuf.clear();
        wpos = 0;
        close_after_write = false;
        epoll_out = false;
    }
};

enum class ParseStatus : uint8_t { Incomplete, Complete, Error };

struct ParsedReq {
    forge::HttpRequest req;
    std::string decoded_chunked;
    size_t total_consumed = 0;
};

// Parse one HTTP/1.1 request from data[start..end). Supports Content-Length and Transfer-Encoding: chunked.
ParseStatus try_parse_request(const char* data, size_t start, size_t end, ParsedReq& out) {
    std::string_view view(data + start, end - start);
    size_t hdr_end = view.find("\r\n\r\n");
    if (hdr_end == std::string_view::npos) {
        if (view.size() > 65536) return ParseStatus::Error;
        return ParseStatus::Incomplete;
    }

    size_t line_end = view.find("\r\n");
    if (line_end == std::string_view::npos || line_end > hdr_end) return ParseStatus::Error;
    std::string_view req_line = view.substr(0, line_end);
    size_t sp1 = req_line.find(' ');
    if (sp1 == std::string_view::npos) return ParseStatus::Error;
    size_t sp2 = req_line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return ParseStatus::Error;

    out.req = forge::HttpRequest{};
    out.req.method = req_line.substr(0, sp1);
    out.req.target = req_line.substr(sp1 + 1, sp2 - sp1 - 1);
    std::string_view version = req_line.substr(sp2 + 1);
    out.req.keep_alive = (version != "HTTP/1.0");

    size_t qpos = out.req.target.find('?');
    if (qpos == std::string_view::npos) {
        out.req.path = out.req.target;
        out.req.query = {};
    } else {
        out.req.path = out.req.target.substr(0, qpos);
        out.req.query = out.req.target.substr(qpos + 1);
    }

    size_t content_length = 0;
    bool has_cl = false;
    bool chunked = false;

    size_t pos = line_end + 2;
    while (pos < hdr_end) {
        size_t eol = view.find("\r\n", pos);
        if (eol == std::string_view::npos || eol > hdr_end) eol = hdr_end;
        std::string_view line = view.substr(pos, eol - pos);
        pos = eol + 2;
        size_t colon = line.find(':');
        if (colon == std::string_view::npos) continue;
        std::string_view k = line.substr(0, colon);
        std::string_view v = trim_ows(line.substr(colon + 1));

        switch (k.size()) {
            case 4:
                if (iequals(k, "host")) out.req.host = v;
                break;
            case 10:
                if (iequals(k, "connection")) {
                    if (iequals(v, "close")) out.req.keep_alive = false;
                    else if (iequals(v, "keep-alive")) out.req.keep_alive = true;
                }
                break;
            case 12:
                if (iequals(k, "content-type")) out.req.content_type = v;
                else if (iequals(k, "git-protocol")) out.req.git_protocol = v;
                break;
            case 13:
                if (iequals(k, "authorization")) out.req.authorization = v;
                break;
            case 14:
                if (iequals(k, "content-length")) {
                    size_t cl = 0;
                    for (char c : v) {
                        if (c < '0' || c > '9') return ParseStatus::Error;
                        cl = cl * 10 + static_cast<size_t>(c - '0');
                        if (cl > 128 * 1024 * 1024) return ParseStatus::Error;
                    }
                    content_length = cl;
                    has_cl = true;
                } else if (iequals(k, "mcp-session-id")) {
                    out.req.mcp_session_id = v;
                }
                break;
            case 17:
                if (iequals(k, "transfer-encoding")) {
                    if (v.find("chunked") != std::string_view::npos || v.find("Chunked") != std::string_view::npos) {
                        chunked = true;
                    }
                }
                break;
            case 20:
                if (iequals(k, "mcp-protocol-version")) out.req.mcp_protocol_version = v;
                break;
            default:
                break;
        }
    }

    size_t body_start = hdr_end + 4;
    if (chunked) {
        out.decoded_chunked.clear();
        size_t cpos = body_start;
        for (;;) {
            size_t crlf = view.find("\r\n", cpos);
            if (crlf == std::string_view::npos) return ParseStatus::Incomplete;
            std::string_view sz_line = view.substr(cpos, crlf - cpos);
            size_t semi = sz_line.find(';');
            if (semi != std::string_view::npos) sz_line = sz_line.substr(0, semi);
            sz_line = trim_ows(sz_line);
            if (sz_line.empty()) return ParseStatus::Error;
            size_t csz = 0;
            for (char c : sz_line) {
                int h = forge::hex_nibble(c);
                if (h < 0) return ParseStatus::Error;
                csz = (csz << 4) | static_cast<size_t>(h);
                if (csz > 128 * 1024 * 1024) return ParseStatus::Error;
            }
            cpos = crlf + 2;
            if (csz == 0) {
                if (cpos + 2 > view.size()) return ParseStatus::Incomplete;
                if (view[cpos] == '\r' && view[cpos + 1] == '\n') {
                    cpos += 2;
                } else {
                    size_t end_trail = view.find("\r\n\r\n", cpos);
                    if (end_trail == std::string_view::npos) return ParseStatus::Incomplete;
                    cpos = end_trail + 4;
                }
                out.req.body = out.decoded_chunked;
                out.total_consumed = cpos;
                return ParseStatus::Complete;
            }
            if (cpos + csz + 2 > view.size()) return ParseStatus::Incomplete;
            out.decoded_chunked.append(view.data() + cpos, csz);
            if (view[cpos + csz] != '\r' || view[cpos + csz + 1] != '\n') return ParseStatus::Error;
            cpos += csz + 2;
        }
    }

    if (has_cl) {
        if (body_start + content_length > view.size()) return ParseStatus::Incomplete;
        out.req.body = view.substr(body_start, content_length);
        out.total_consumed = body_start + content_length;
        return ParseStatus::Complete;
    }

    out.req.body = {};
    out.total_consumed = body_start;
    return ParseStatus::Complete;
}

void dispatch_request(forge::ForgeStore& store, const forge::HttpRequest& req, forge::HttpResponse& res) {
    if (req.method == "GET" && req.path == "/healthz") {
        static const std::string kHealthOk =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "X-GitHub-Request-Id: 1\r\n"
            "Content-Length: 11\r\n\r\n"
            "{\"ok\":true}";
        if (req.keep_alive) {
            res.set_prebuilt(kHealthOk);
            return;
        }
        forge::build_json_response(res, 200, "{\"ok\":true}", store.next_request_id(), false);
        return;
    }

    // Zero-allocation cached fast paths (GET /issues/{n}, Git v2 info/refs, ls-refs, shallow-1 fetch)
    if (forge::try_rest_fast_readonly(store, req, res)) return;
    if (forge::try_git_fast_readonly(store, req, res)) return;

    if (forge::handle_rest(store, req, res)) return;
    if (forge::handle_graphql(store, req, res)) return;
    if (forge::handle_mcp(store, req, res)) return;
    if (forge::handle_git_http(store, req, res)) return;

    forge::build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
}

int64_t parse_trial_epoch(const char* env_val) {
    if (!env_val || !*env_val) return 1735689600;
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    if (std::sscanf(env_val, "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) == 6) {
        std::tm t{};
        t.tm_year = y - 1900;
        t.tm_mon = mo - 1;
        t.tm_mday = d;
        t.tm_hour = h;
        t.tm_min = mi;
        t.tm_sec = s;
        return static_cast<int64_t>(timegm(&t));
    }
    return 1735689600;
}

} // namespace

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGINT, on_signal);

    uint16_t bind_port = 0;
    bool env_mode = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            bind_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--env-mode") == 0) {
            env_mode = true;
        }
    }

    const char* token_env = std::getenv("MAKEFUN_SHOP_TOKEN");
    const char* login_env = std::getenv("MAKEFUN_FORGE_LOGIN");
    const char* now_env = std::getenv("MAKEFUN_TRIAL_NOW");

    std::string viewer_login = (login_env && *login_env) ? std::string(login_env) : std::string("adaiversen");
    std::string auth_token = (token_env && *token_env) ? std::string(token_env) : std::string("");
    int64_t base_epoch = parse_trial_epoch(now_env);

    forge::ForgeStore store(std::move(viewer_login), std::move(auth_token), base_epoch);

    int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listen_fd < 0) {
        std::perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(listen_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(bind_port);
    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::perror("bind");
        close(listen_fd);
        return 1;
    }
    if (listen(listen_fd, 512) < 0) {
        std::perror("listen");
        close(listen_fd);
        return 1;
    }

    socklen_t alen = sizeof(addr);
    if (getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &alen) < 0) {
        std::perror("getsockname");
        close(listen_fd);
        return 1;
    }
    uint16_t actual_port = ntohs(addr.sin_port);

    const char* env_ip = std::getenv("MAKEFUN_ENV_IP");
    const char* env_port_s = std::getenv("MAKEFUN_ENV_PORT");
    const char* env_host = std::getenv("MAKEFUN_ENV_HOST");
    const char* env_prefix = std::getenv("MAKEFUN_ENV_PREFIX");
    uint16_t env_port = (env_port_s && *env_port_s) ? static_cast<uint16_t>(std::atoi(env_port_s)) : 0;
    std::string done_req;

    if (env_mode) {
        if (!env_ip || !*env_ip || env_port == 0) {
            std::fprintf(stderr, "[cobalt-forge] missing MAKEFUN_ENV_IP/PORT in --env-mode\n");
            close(listen_fd);
            return 1;
        }
        const char* host_h = (env_host && *env_host) ? env_host : env_ip;
        const char* pref = env_prefix ? env_prefix : "";
        if (!register_with_env(env_ip, env_port, host_h, pref, actual_port)) {
            std::fprintf(stderr, "[cobalt-forge] failed to register port %u with env\n", static_cast<unsigned>(actual_port));
            close(listen_fd);
            return 1;
        }
        done_req =
            "GET " + std::string(pref) + "/done HTTP/1.1\r\n"
            "Host: " + std::string(host_h) + "\r\n"
            "Connection: close\r\n\r\n";
    } else {
        std::printf("PORT %u\n", static_cast<unsigned>(actual_port));
        std::fflush(stdout);
    }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        std::perror("epoll_create1");
        close(listen_fd);
        return 1;
    }

    epoll_event lev{};
    lev.events = EPOLLIN;
    lev.data.fd = listen_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &lev) < 0) {
        std::perror("epoll_ctl listen");
        close(epfd);
        close(listen_fd);
        return 1;
    }

    std::vector<Conn> conns(512);

    auto close_conn = [&](int fd) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
        close(fd);
        if (fd >= 0 && static_cast<size_t>(fd) < conns.size()) {
            conns[static_cast<size_t>(fd)].reset();
        }
    };

    auto set_epoll_out = [&](Conn& c, bool enable) {
        if (c.epoll_out == enable) return;
        epoll_event ev{};
        ev.events = static_cast<uint32_t>(EPOLLIN) | (enable ? static_cast<uint32_t>(EPOLLOUT) : 0u);
        ev.data.fd = c.fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, c.fd, &ev);
        c.epoll_out = enable;
    };

    auto flush_write = [&](Conn& c) -> bool {
        while (c.wpos < c.wbuf.size()) {
            ssize_t n = send(c.fd, c.wbuf.data() + c.wpos, c.wbuf.size() - c.wpos, MSG_NOSIGNAL);
            if (n > 0) {
                c.wpos += static_cast<size_t>(n);
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                set_epoll_out(c, true);
                return true;
            } else {
                return false;
            }
        }
        c.wbuf.clear();
        c.wpos = 0;
        set_epoll_out(c, false);
        return !c.close_after_write;
    };

    auto send_response = [&](Conn& c, const char* data, size_t len, bool close_conn_after) -> bool {
        if (close_conn_after) c.close_after_write = true;
        if (c.wbuf.empty()) {
            size_t sent = 0;
            while (sent < len) {
                ssize_t n = send(c.fd, data + sent, len - sent, MSG_NOSIGNAL);
                if (n > 0) {
                    sent += static_cast<size_t>(n);
                } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    c.wbuf.assign(data + sent, len - sent);
                    c.wpos = 0;
                    set_epoll_out(c, true);
                    return true;
                } else {
                    return false;
                }
            }
            return !c.close_after_write;
        }
        c.wbuf.append(data, len);
        return flush_write(c);
    };

    std::vector<epoll_event> events(128);
    char fast_buf[65536];
    ParsedReq parsed;
    forge::HttpResponse res;
    res.owned_raw.reserve(8192);

    while (!g_stop) {
        int nfds = epoll_wait(epfd, events.data(), static_cast<int>(events.size()), 200);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (nfds == 0) {
            // Only poll /done when completely idle for >= 200ms (never interrupts active benchmarks!)
            if (env_mode && poll_env_done(env_ip, env_port, done_req)) {
                break;
            }
            continue;
        }

        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;
            uint32_t ev = events[i].events;

            if (fd == listen_fd) {
                for (;;) {
                    sockaddr_in caddr{};
                    socklen_t clen = sizeof(caddr);
                    int cfd = accept4(listen_fd, reinterpret_cast<sockaddr*>(&caddr), &clen, SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if (cfd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        break;
                    }
                    int nodelay = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
                    epoll_event cev{};
                    cev.events = EPOLLIN;
                    cev.data.fd = cfd;
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &cev) < 0) {
                        close(cfd);
                        continue;
                    }
                    if (static_cast<size_t>(cfd) >= conns.size()) {
                        conns.resize(static_cast<size_t>(cfd) + 64);
                    }
                    Conn& nc = conns[static_cast<size_t>(cfd)];
                    nc.reset();
                    nc.fd = cfd;
                    nc.active = true;
                }
                continue;
            }

            if (fd < 0 || static_cast<size_t>(fd) >= conns.size() || !conns[static_cast<size_t>(fd)].active) continue;
            Conn& c = conns[static_cast<size_t>(fd)];

            if (ev & (EPOLLERR | EPOLLHUP)) {
                close_conn(fd);
                continue;
            }

            if (ev & EPOLLOUT) {
                if (!flush_write(c)) {
                    close_conn(fd);
                    continue;
                }
            }

            if (ev & EPOLLIN) {
                // Fast zero-copy path: read straight into L1-hot fast_buf when no partial request is buffered
                if (c.rbuf.empty()) {
                    ssize_t n = recv(fd, fast_buf, sizeof(fast_buf), 0);
                    if (n > 0) {
                        size_t pos = 0;
                        size_t len = static_cast<size_t>(n);
                        bool alive = true;
                        while (alive && pos < len) {
                            ParseStatus st = try_parse_request(fast_buf, pos, len, parsed);
                            if (st == ParseStatus::Incomplete) {
                                c.rbuf.assign(fast_buf + pos, len - pos);
                                c.rpos = 0;
                                pos = len;
                                break;
                            }
                            if (st == ParseStatus::Error) {
                                forge::build_error_json(res, 400, "Bad Request", store.next_request_id(), false);
                                send_response(c, res.owned_raw.data(), res.owned_raw.size(), true);
                                alive = false;
                                break;
                            }
                            pos += parsed.total_consumed;
                            res.raw_ptr = nullptr;
                            res.raw_len = 0;
                            dispatch_request(store, parsed.req, res);
                            const char* out_ptr = res.raw_ptr ? res.raw_ptr : res.owned_raw.data();
                            size_t out_len = res.raw_ptr ? res.raw_len : res.owned_raw.size();
                            if (!send_response(c, out_ptr, out_len, !parsed.req.keep_alive)) {
                                alive = false;
                                break;
                            }
                        }
                        if (!alive) close_conn(fd);
                        continue;
                    } else if (n == 0) {
                        if (c.wbuf.empty()) close_conn(fd);
                        continue;
                    } else {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) close_conn(fd);
                        continue;
                    }
                }

                // Buffered path for multi-packet requests
                bool peer_closed = false;
                bool fatal = false;
                for (;;) {
                    ssize_t n = recv(fd, fast_buf, sizeof(fast_buf), 0);
                    if (n > 0) {
                        c.rbuf.append(fast_buf, static_cast<size_t>(n));
                        if (n < static_cast<ssize_t>(sizeof(fast_buf))) break;
                    } else if (n == 0) {
                        peer_closed = true;
                        break;
                    } else {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        fatal = true;
                        break;
                    }
                }
                if (fatal) {
                    close_conn(fd);
                    continue;
                }

                bool alive = true;
                while (alive && c.rpos < c.rbuf.size()) {
                    ParseStatus st = try_parse_request(c.rbuf.data(), c.rpos, c.rbuf.size(), parsed);
                    if (st == ParseStatus::Incomplete) break;
                    if (st == ParseStatus::Error) {
                        forge::build_error_json(res, 400, "Bad Request", store.next_request_id(), false);
                        send_response(c, res.owned_raw.data(), res.owned_raw.size(), true);
                        alive = false;
                        break;
                    }
                    c.rpos += parsed.total_consumed;
                    res.raw_ptr = nullptr;
                    res.raw_len = 0;
                    dispatch_request(store, parsed.req, res);

                    const char* out_ptr = res.raw_ptr ? res.raw_ptr : res.owned_raw.data();
                    size_t out_len = res.raw_ptr ? res.raw_len : res.owned_raw.size();
                    if (!send_response(c, out_ptr, out_len, !parsed.req.keep_alive)) {
                        alive = false;
                        break;
                    }
                }

                if (!alive) {
                    close_conn(fd);
                    continue;
                }

                if (c.rpos > 0) {
                    if (c.rpos == c.rbuf.size()) {
                        c.rbuf.clear();
                        c.rpos = 0;
                    } else if (c.rpos > 32768) {
                        c.rbuf.erase(0, c.rpos);
                        c.rpos = 0;
                    }
                }

                if (peer_closed && c.wbuf.empty()) {
                    close_conn(fd);
                }
            }
        }
    }

    for (auto& c : conns) {
        if (c.active) close(c.fd);
    }
    close(epfd);
    close(listen_fd);
    return 0;
}
