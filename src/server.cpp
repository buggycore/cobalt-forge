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

inline std::string_view strip_nl(std::string_view s) noexcept {
    if (!s.empty() && s.back() == '\n') s.remove_suffix(1);
    if (!s.empty() && s.back() == '\r') s.remove_suffix(1);
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
        ssize_t n = write(fd, req_bytes.data() + sent, req_bytes.size() - sent);
        if (n <= 0) {
            close(fd);
            return false;
        }
        sent += static_cast<size_t>(n);
    }

    std::string resp;
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
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

// Fast single-pass HTTP/1.1 request parser with memchr + first-char header filter.
ParseStatus try_parse_request(const char* data, size_t start, size_t end, ParsedReq& out) {
    std::string_view view(data + start, end - start);
    size_t hdr_end = view.find("\r\n\r\n");
    if (hdr_end == std::string_view::npos) {
        if (view.size() > 65536) return ParseStatus::Error;
        return ParseStatus::Incomplete;
    }

    const char* first_lf = static_cast<const char*>(std::memchr(view.data(), '\n', hdr_end));
    if (!first_lf) return ParseStatus::Error;
    size_t line_end = static_cast<size_t>(first_lf - view.data());
    size_t req_len = (line_end > 0 && view[line_end - 1] == '\r') ? (line_end - 1) : line_end;
    std::string_view req_line = view.substr(0, req_len);
    size_t sp1 = req_line.find(' ');
    if (sp1 == std::string_view::npos) return ParseStatus::Error;
    size_t sp2 = req_line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return ParseStatus::Error;

    out.req = forge::HttpRequest{};
    out.req.method = req_line.substr(0, sp1);
    out.req.target = req_line.substr(sp1 + 1, sp2 - sp1 - 1);
    std::string_view version = req_line.substr(sp2 + 1);
    out.req.keep_alive = (version != "HTTP/1.0");

    const char* qp = static_cast<const char*>(std::memchr(out.req.target.data(), '?', out.req.target.size()));
    if (!qp) {
        out.req.path = out.req.target;
        out.req.query = {};
    } else {
        size_t qpos = static_cast<size_t>(qp - out.req.target.data());
        out.req.path = out.req.target.substr(0, qpos);
        out.req.query = out.req.target.substr(qpos + 1);
    }

    size_t content_length = 0;
    bool has_cl = false;
    bool chunked = false;

    size_t pos = line_end + 1;
    while (pos < hdr_end) {
        const char* lf = static_cast<const char*>(std::memchr(view.data() + pos, '\n', hdr_end - pos));
        size_t eol = lf ? static_cast<size_t>(lf - view.data()) : hdr_end;
        size_t ltrim = (eol > pos && view[eol - 1] == '\r') ? (eol - 1) : eol;
        std::string_view line = view.substr(pos, ltrim - pos);
        pos = (eol < hdr_end) ? (eol + 1) : hdr_end;
        if (line.empty()) continue;
        unsigned char c0 = static_cast<unsigned char>(line[0]);
        if (c0 >= 'A' && c0 <= 'Z') c0 += 32;
        if (c0 != 'a' && c0 != 'c' && c0 != 'g' && c0 != 'h' && c0 != 'm' && c0 != 't') continue;
        const char* col_p = static_cast<const char*>(std::memchr(line.data(), ':', line.size()));
        if (!col_p) continue;
        size_t colon = static_cast<size_t>(col_p - line.data());
        std::string_view k = line.substr(0, colon);
        std::string_view v = trim_ows(line.substr(colon + 1));

        switch (k.size()) {
            case 4:
                if (c0 == 'h' && iequals(k, "host")) out.req.host = v;
                break;
            case 10:
                if (c0 == 'c' && iequals(k, "connection")) {
                    if (iequals(v, "close")) out.req.keep_alive = false;
                    else if (iequals(v, "keep-alive")) out.req.keep_alive = true;
                }
                break;
            case 12:
                if (c0 == 'c' && iequals(k, "content-type")) out.req.content_type = v;
                else if (c0 == 'g' && iequals(k, "git-protocol")) out.req.git_protocol = v;
                break;
            case 13:
                if (c0 == 'a' && iequals(k, "authorization")) out.req.authorization = v;
                break;
            case 14:
                if (c0 == 'c' && iequals(k, "content-length")) {
                    size_t cl = 0;
                    for (char c : v) {
                        if (c < '0' || c > '9') return ParseStatus::Error;
                        cl = cl * 10 + static_cast<size_t>(c - '0');
                        if (cl > 128 * 1024 * 1024) return ParseStatus::Error;
                    }
                    content_length = cl;
                    has_cl = true;
                } else if (c0 == 'm' && iequals(k, "mcp-session-id")) {
                    out.req.mcp_session_id = v;
                }
                break;
            case 17:
                if (c0 == 't' && iequals(k, "transfer-encoding")) {
                    if (v.find("chunked") != std::string_view::npos || v.find("Chunked") != std::string_view::npos) {
                        chunked = true;
                    }
                }
                break;
            case 20:
                if (c0 == 'm' && iequals(k, "mcp-protocol-version")) out.req.mcp_protocol_version = v;
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

// Single-threaded L1 hot cache: zero hash-map lookups on repeated GET /issues/{n} and 50-way clone!
struct HotL1 {
    bool issue_valid = false;
    std::string issue_path;
    const std::string* issue_http = nullptr;

    bool clone_valid = false;
    std::string clone_owner_repo;
    const std::string* clone_ls_refs = nullptr;
    forge::Oid clone_want0{};
    const std::string* clone_fetch = nullptr;
};

inline bool split_git_path(
    std::string_view p, std::string_view& owner, std::string_view& repo_no_git, std::string_view& tail) noexcept {
    if (p.size() < 12 || p[0] != '/') return false;
    if (p.substr(0, 5) == "/api/") return false;
    size_t s1 = p.find('/', 1);
    if (s1 == std::string_view::npos) return false;
    owner = p.substr(1, s1 - 1);
    size_t s2 = p.find('/', s1 + 1);
    if (s2 == std::string_view::npos) return false;
    repo_no_git = p.substr(s1 + 1, s2 - s1 - 1);
    if (repo_no_git.size() > 4 && repo_no_git.substr(repo_no_git.size() - 4) == ".git") {
        repo_no_git.remove_suffix(4);
    }
    tail = p.substr(s2);
    return true;
}

inline bool match_owner_repo(std::string_view owner_repo, std::string_view owner, std::string_view repo) noexcept {
    return owner_repo.size() == owner.size() + 1 + repo.size() &&
           owner_repo[owner.size()] == '/' &&
           owner_repo.substr(0, owner.size()) == owner &&
           owner_repo.substr(owner.size() + 1) == repo;
}

bool try_l1_fast(const HotL1& l1, const forge::ForgeStore& store, const forge::HttpRequest& req, forge::HttpResponse& res) noexcept {
    if (!req.keep_alive) return false;

    if (l1.issue_valid && req.method == "GET" && req.query.empty() && req.path == l1.issue_path) {
        if (store.check_auth(req.authorization)) {
            res.set_prebuilt(*l1.issue_http);
            return true;
        }
        return false;
    }

    if (l1.clone_valid) {
        std::string_view owner, repo, tail;
        if (split_git_path(req.path, owner, repo, tail) &&
            match_owner_repo(l1.clone_owner_repo, owner, repo) &&
            store.check_auth(req.authorization)) {
            if (req.method == "GET" && tail == "/info/refs" &&
                req.query == "service=git-upload-pack" &&
                req.git_protocol.find("version=2") != std::string_view::npos) {
                res.set_prebuilt(forge::git_v2_info_refs_http());
                return true;
            }
            if (req.method == "POST" && tail == "/git-upload-pack") {
                std::string_view buf = req.body;
                size_t pos = 0;
                std::string_view command;
                bool in_args = false;
                bool peel = false, symrefs = false, has_prefix = false;
                int deepen = 0, want_count = 0, have_count = 0, shallow_count = 0;
                forge::Oid want0{};
                while (pos + 4 <= buf.size()) {
                    unsigned len = 0;
                    for (int i = 0; i < 4; ++i) {
                        int n = forge::hex_nibble(buf[pos + i]);
                        if (n < 0) return false;
                        len = (len << 4) | static_cast<unsigned>(n);
                    }
                    if (len == 0) break;
                    if (len == 1) { in_args = true; pos += 4; continue; }
                    if (len == 2) { pos += 4; continue; }
                    if (len < 4 || pos + len > buf.size()) return false;
                    std::string_view line = strip_nl(buf.substr(pos + 4, len - 4));
                    pos += len;
                    if (!in_args) {
                        if (line.size() > 8 && line.substr(0, 8) == "command=") command = line.substr(8);
                    } else if (command == "ls-refs") {
                        if (line == "peel") peel = true;
                        else if (line == "symrefs") symrefs = true;
                        else if (line.size() >= 11 && line.substr(0, 11) == "ref-prefix ") has_prefix = true;
                    } else if (command == "fetch") {
                        if (line.size() == 45 && line.substr(0, 5) == "want ") {
                            if (want_count == 0 && !forge::parse_oid(line.substr(5), want0)) return false;
                            ++want_count;
                        } else if (line.size() == 45 && line.substr(0, 5) == "have ") {
                            ++have_count;
                        } else if (line.size() == 48 && line.substr(0, 8) == "shallow ") {
                            ++shallow_count;
                        } else if (line.size() > 7 && line.substr(0, 7) == "deepen ") {
                            int d = 0;
                            for (size_t k = 7; k < line.size(); ++k) {
                                if (line[k] < '0' || line[k] > '9') return false;
                                d = d * 10 + (line[k] - '0');
                            }
                            deepen = d;
                        }
                    }
                }
                if (command == "ls-refs" && peel && symrefs && !has_prefix && l1.clone_ls_refs) {
                    res.set_prebuilt(*l1.clone_ls_refs);
                    return true;
                }
                if (command == "fetch" && deepen == 1 && want_count == 1 && have_count == 0 &&
                    shallow_count == 0 && l1.clone_fetch && want0 == l1.clone_want0) {
                    res.set_prebuilt(*l1.clone_fetch);
                    return true;
                }
            }
        }
    }
    return false;
}

void dispatch_request(HotL1& l1, forge::ForgeStore& store, const forge::HttpRequest& req, forge::HttpResponse& res) {
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

    if (try_l1_fast(l1, store, req, res)) return;

    std::string_view git_owner, git_repo, git_tail;
    bool is_git_ro = split_git_path(req.path, git_owner, git_repo, git_tail) &&
                     ((req.method == "GET" && git_tail == "/info/refs") ||
                      (req.method == "POST" && git_tail == "/git-upload-pack"));
    if (req.method != "GET" && !is_git_ro) {
        l1.issue_valid = false;
        l1.clone_valid = false;
    }

    if (forge::try_rest_fast_readonly(store, req, res) ||
        forge::try_git_fast_readonly(store, req, res) ||
        forge::handle_rest(store, req, res) ||
        forge::handle_graphql(store, req, res) ||
        forge::handle_mcp(store, req, res) ||
        forge::handle_git_http(store, req, res)) {
        if (req.keep_alive) {
            if (req.method == "GET" && req.query.empty() && res.raw_ptr != nullptr &&
                req.path.size() > 14 && req.path.substr(0, 14) == "/api/v3/repos/" &&
                req.path.find("/issues/") != std::string_view::npos) {
                std::string_view rest = req.path.substr(14);
                size_t s1 = rest.find('/');
                size_t s2 = (s1 != std::string_view::npos) ? rest.find('/', s1 + 1) : std::string_view::npos;
                if (s2 != std::string_view::npos && rest.substr(s2, 8) == "/issues/") {
                    forge::Repo* r = store.find_repo(rest.substr(0, s1), rest.substr(s1 + 1, s2 - s1 - 1));
                    uint32_t num = static_cast<uint32_t>(std::atoi(std::string(rest.substr(s2 + 8)).c_str()));
                    if (r) {
                        if (forge::Issue* iss = r->find_issue(num); iss && !iss->cached_http_response.empty()) {
                            l1.issue_path.assign(req.path);
                            l1.issue_http = &iss->cached_http_response;
                            l1.issue_valid = true;
                        }
                    }
                }
            } else if (is_git_ro && req.method == "POST" && git_tail == "/git-upload-pack") {
                forge::Repo* r = store.find_repo(git_owner, git_repo);
                if (r && (!r->cached_ls_refs_http.empty() || !r->shallow1_http_cache.empty())) {
                    l1.clone_owner_repo = std::string(git_owner) + "/" + std::string(git_repo);
                    l1.clone_ls_refs = (r->cached_ls_refs_version == r->ref_version && !r->cached_ls_refs_http.empty())
                        ? &r->cached_ls_refs_http : nullptr;
                    if (!r->shallow1_http_cache.empty()) {
                        auto it = r->shallow1_http_cache.begin();
                        l1.clone_want0 = it->first;
                        l1.clone_fetch = &it->second;
                    } else {
                        l1.clone_fetch = nullptr;
                    }
                    l1.clone_valid = true;
                }
            }
        }
        return;
    }

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
    HotL1 l1;

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
            ssize_t n = write(c.fd, c.wbuf.data() + c.wpos, c.wbuf.size() - c.wpos);
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
                ssize_t n = write(c.fd, data + sent, len - sent);
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
                if (c.rbuf.empty()) {
                    ssize_t n = read(fd, fast_buf, sizeof(fast_buf));
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
                            dispatch_request(l1, store, parsed.req, res);
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

                bool peer_closed = false;
                bool fatal = false;
                for (;;) {
                    ssize_t n = read(fd, fast_buf, sizeof(fast_buf));
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
                    dispatch_request(l1, store, parsed.req, res);

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
