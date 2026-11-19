#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <sys/socket.h>
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

inline bool send_all(int fd, const char* data, size_t len) noexcept {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += static_cast<size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

void dispatch_request(forge::ForgeStore& store, const forge::HttpRequest& req, forge::HttpResponse& res) {
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

struct ServerCtx {
    forge::ForgeStore* store = nullptr;
    std::shared_mutex store_mu;

    std::mutex pool_mu;
    std::condition_variable pool_cv;
    std::vector<int> fd_queue;
    size_t idle_workers = 0;
    size_t total_workers = 0;
};

void handle_connection(int fd, ServerCtx& ctx, std::string& rbuf, ParsedReq& parsed, forge::HttpResponse& res) {
    static const std::string kHealthOk =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "X-GitHub-Request-Id: hea17h00\r\n"
        "Content-Length: 11\r\n\r\n"
        "{\"ok\":true}";

    size_t rpos = 0;
    size_t rlen = 0;

    for (;;) {
        bool alive = true;
        while (alive && rpos < rlen) {
            ParseStatus st = try_parse_request(rbuf.data(), rpos, rlen, parsed);
            if (st == ParseStatus::Incomplete) break;
            if (st == ParseStatus::Error) {
                static constexpr char kBadReq[] =
                    "HTTP/1.1 400 Bad Request\r\n"
                    "Content-Type: application/json\r\n"
                    "X-GitHub-Request-Id: bad00400\r\n"
                    "Connection: close\r\n"
                    "Content-Length: 25\r\n\r\n"
                    "{\"message\":\"Bad Request\"}";
                send_all(fd, kBadReq, sizeof(kBadReq) - 1);
                return;
            }
            rpos += parsed.total_consumed;
            const auto& req = parsed.req;

            // Lock-free healthz fast path
            if (req.method == "GET" && req.path == "/healthz" && req.keep_alive) {
                if (!send_all(fd, kHealthOk.data(), kHealthOk.size())) return;
                continue;
            }

            // Fast read-only shared_lock path (GET /issues/{n}, git v2 info/refs, ls-refs, shallow-1 fetch)
            bool handled = false;
            bool send_ok = true;
            if (req.keep_alive) {
                std::shared_lock<std::shared_mutex> rlk(ctx.store_mu);
                res.raw_ptr = nullptr;
                res.raw_len = 0;
                if (forge::try_rest_fast_readonly(*ctx.store, req, res) ||
                    forge::try_git_fast_readonly(*ctx.store, req, res)) {
                    handled = true;
                    send_ok = send_all(fd, res.raw_ptr, res.raw_len);
                }
            }
            if (handled) {
                if (!send_ok) return;
                continue;
            }

            // General path under unique_lock; release lock before network send when using thread-local owned_raw
            res.raw_ptr = nullptr;
            res.raw_len = 0;
            {
                std::unique_lock<std::shared_mutex> wlk(ctx.store_mu);
                if (req.method == "GET" && req.path == "/healthz") {
                    forge::build_json_response(res, 200, "{\"ok\":true}", ctx.store->next_request_id(), req.keep_alive);
                } else {
                    dispatch_request(*ctx.store, req, res);
                }
                if (res.raw_ptr != nullptr) {
                    send_ok = send_all(fd, res.raw_ptr, res.raw_len);
                }
            }
            if (res.raw_ptr == nullptr) {
                send_ok = send_all(fd, res.owned_raw.data(), res.owned_raw.size());
            }
            if (!send_ok || !req.keep_alive) {
                return;
            }
        }

        if (rpos > 0) {
            if (rpos == rlen) {
                rpos = 0;
                rlen = 0;
            } else if (rpos > 32768) {
                std::memmove(rbuf.data(), rbuf.data() + rpos, rlen - rpos);
                rlen -= rpos;
                rpos = 0;
            }
        }

        if (rbuf.size() - rlen < 16384) {
            rbuf.resize(rbuf.size() * 2);
        }

        ssize_t n = recv(fd, rbuf.data() + rlen, rbuf.size() - rlen, 0);
        if (n > 0) {
            rlen += static_cast<size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            if (g_stop) return;
            continue;
        } else {
            return;
        }
    }
}

void* worker_entry(void* arg) {
    auto* ctx = static_cast<ServerCtx*>(arg);
    std::string rbuf(65536, '\0');
    ParsedReq parsed;
    forge::HttpResponse res;
    res.owned_raw.reserve(4096);

    for (;;) {
        int fd = -1;
        {
            std::unique_lock<std::mutex> lk(ctx->pool_mu);
            ++ctx->idle_workers;
            ctx->pool_cv.wait(lk, [&] { return !ctx->fd_queue.empty(); });
            --ctx->idle_workers;
            fd = ctx->fd_queue.back();
            ctx->fd_queue.pop_back();
        }
        handle_connection(fd, *ctx, rbuf, parsed, res);
        close(fd);
        if (rbuf.size() > 262144) {
            std::string shrunk(65536, '\0');
            rbuf.swap(shrunk);
        }
    }
    return nullptr;
}

void spawn_worker(ServerCtx* ctx) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 256 * 1024);
    pthread_t tid{};
    if (pthread_create(&tid, &attr, worker_entry, ctx) != 0) {
        // Fallback: shouldn't happen below 128 threads
    }
    pthread_attr_destroy(&attr);
}

} // namespace

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // no SA_RESTART so accept() wakes on SIGTERM
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);

    uint16_t bind_port = 0;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            bind_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        }
    }

    const char* token_env = std::getenv("MAKEFUN_SHOP_TOKEN");
    const char* login_env = std::getenv("MAKEFUN_FORGE_LOGIN");
    const char* now_env = std::getenv("MAKEFUN_TRIAL_NOW");

    std::string viewer_login = (login_env && *login_env) ? std::string(login_env) : std::string("adaiversen");
    std::string auth_token = (token_env && *token_env) ? std::string(token_env) : std::string("");
    int64_t base_epoch = parse_trial_epoch(now_env);

    forge::ForgeStore store(std::move(viewer_login), std::move(auth_token), base_epoch);
    ServerCtx ctx;
    ctx.store = &store;
    ctx.fd_queue.reserve(128);

    // Pre-warm worker threads so concurrent bursts (e.g., 50 clones) incur zero thread-spawn latency
    constexpr size_t kInitialWorkers = 56;
    constexpr size_t kMaxWorkers = 128;
    ctx.total_workers = kInitialWorkers;
    for (size_t i = 0; i < kInitialWorkers; ++i) {
        spawn_worker(&ctx);
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
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
    std::printf("PORT %u\n", static_cast<unsigned>(actual_port));
    std::fflush(stdout);

    while (!g_stop) {
        sockaddr_in caddr{};
        socklen_t clen = sizeof(caddr);
        int cfd = accept4(listen_fd, reinterpret_cast<sockaddr*>(&caddr), &clen, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            if (g_stop) break;
            continue;
        }
        int nodelay = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

        {
            std::lock_guard<std::mutex> lk(ctx.pool_mu);
            ctx.fd_queue.push_back(cfd);
            if (ctx.idle_workers == 0 && ctx.total_workers < kMaxWorkers) {
                ++ctx.total_workers;
                spawn_worker(&ctx);
            }
        }
        ctx.pool_cv.notify_one();
    }

    close(listen_fd);
    _exit(0);
}
