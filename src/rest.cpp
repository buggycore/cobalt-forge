#include "rest.hpp"

#include <algorithm>
#include <cstdlib>
#include <queue>
#include <unordered_set>

namespace forge {

namespace {

std::string_view qparam(std::string_view query, std::string_view key) noexcept {
    size_t pos = 0;
    while (pos < query.size()) {
        size_t amp = query.find('&', pos);
        if (amp == std::string_view::npos) amp = query.size();
        std::string_view part = query.substr(pos, amp - pos);
        size_t eq = part.find('=');
        if (eq != std::string_view::npos && part.substr(0, eq) == key) {
            return part.substr(eq + 1);
        }
        pos = amp + 1;
    }
    return {};
}

int qparam_int(std::string_view query, std::string_view key, int def_val) noexcept {
    auto v = qparam(query, key);
    if (v.empty()) return def_val;
    int out = 0;
    for (char c : v) {
        if (c < '0' || c > '9') return def_val;
        out = out * 10 + (c - '0');
        if (out > 1000000) return def_val;
    }
    return out;
}

bool parse_uint32(std::string_view s, uint32_t& out) noexcept {
    if (s.empty() || s.size() > 10) return false;
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<uint64_t>(c - '0');
        if (v > 0xffffffffull) return false;
    }
    out = static_cast<uint32_t>(v);
    return true;
}

bool parse_json_body(const HttpRequest& req, JsonValue& out, ForgeStore& store, HttpResponse& res) {
    if (req.body.empty()) {
        out = JsonValue::make_object();
        return true;
    }
    if (!parse_json(req.body, out) || !out.is_object()) {
        build_error_json(res, 400, "Problems parsing JSON", store.next_request_id(), req.keep_alive);
        return false;
    }
    return true;
}

void split_segments(std::string_view p, std::vector<std::string_view>& out) {
    out.clear();
    size_t pos = 0;
    while (pos < p.size()) {
        while (pos < p.size() && p[pos] == '/') ++pos;
        if (pos >= p.size()) break;
        size_t slash = p.find('/', pos);
        if (slash == std::string_view::npos) {
            out.push_back(p.substr(pos));
            break;
        }
        out.push_back(p.substr(pos, slash - pos));
        pos = slash + 1;
    }
}

// Zero-alloc fast-path JSON extractor for {"title":"...","body":"..."} without building a JsonValue DOM.
bool fast_parse_issue_create(
    std::string_view s, std::string_view& title_sv, std::string_view& body_sv, std::string& title_buf, std::string& body_buf) {
    size_t i = 0;
    auto skip_ws = [&]() {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) ++i;
    };
    auto parse_str_sv = [&](std::string_view& sv_out, std::string& buf_out) -> bool {
        if (i >= s.size() || s[i] != '"') return false;
        ++i;
        size_t start = i;
        while (i < s.size()) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (c == '"') {
                sv_out = s.substr(start, i - start);
                ++i;
                return true;
            }
            if (c == '\\') {
                buf_out.assign(s.data() + start, i - start);
                for (;;) {
                    ++i;
                    if (i >= s.size()) return false;
                    char esc = s[i++];
                    switch (esc) {
                        case '"': buf_out.push_back('"'); break;
                        case '\\': buf_out.push_back('\\'); break;
                        case '/': buf_out.push_back('/'); break;
                        case 'b': buf_out.push_back('\b'); break;
                        case 'f': buf_out.push_back('\f'); break;
                        case 'n': buf_out.push_back('\n'); break;
                        case 'r': buf_out.push_back('\r'); break;
                        case 't': buf_out.push_back('\t'); break;
                        default: return false;
                    }
                    size_t seg_start = i;
                    while (i < s.size()) {
                        unsigned char ch = static_cast<unsigned char>(s[i]);
                        if (ch == '"') {
                            buf_out.append(s.data() + seg_start, i - seg_start);
                            ++i;
                            sv_out = buf_out;
                            return true;
                        }
                        if (ch == '\\') {
                            buf_out.append(s.data() + seg_start, i - seg_start);
                            break;
                        }
                        if (ch < 0x20) return false;
                        ++i;
                    }
                    if (i >= s.size()) return false;
                }
            } else if (c < 0x20) {
                return false;
            } else {
                ++i;
            }
        }
        return false;
    };

    skip_ws();
    if (i >= s.size() || s[i] != '{') return false;
    ++i;
    skip_ws();
    if (i < s.size() && s[i] == '}') return false;

    bool has_title = false;
    title_sv = {};
    body_sv = {};
    for (;;) {
        skip_ws();
        if (i >= s.size() || s[i] != '"') return false;
        ++i;
        size_t kstart = i;
        while (i < s.size() && s[i] != '"' && s[i] != '\\') ++i;
        if (i >= s.size() || s[i] != '"') return false;
        std::string_view key = s.substr(kstart, i - kstart);
        ++i;
        skip_ws();
        if (i >= s.size() || s[i] != ':') return false;
        ++i;
        skip_ws();
        if (key == "title") {
            if (!parse_str_sv(title_sv, title_buf)) return false;
            has_title = !title_sv.empty();
        } else if (key == "body") {
            if (i + 4 <= s.size() && s.substr(i, 4) == "null") {
                body_sv = {};
                i += 4;
            } else if (!parse_str_sv(body_sv, body_buf)) {
                return false;
            }
        } else {
            return false;
        }
        skip_ws();
        if (i >= s.size()) return false;
        if (s[i] == ',') {
            ++i;
            continue;
        }
        if (s[i] == '}') {
            ++i;
            break;
        }
        return false;
    }
    skip_ws();
    return has_title && i == s.size();
}

} // namespace

bool try_rest_fast_readonly(const ForgeStore& store, const HttpRequest& req, HttpResponse& res) {
    if (!req.keep_alive || req.method != "GET") return false;
    std::string_view p = req.path;
    if (p.size() <= 14 || p.substr(0, 14) != "/api/v3/repos/") return false;
    if (!store.check_auth(req.authorization)) return false;

    std::string_view rest = p.substr(14);
    size_t s1 = rest.find('/');
    if (s1 == std::string_view::npos) return false;
    size_t s2 = rest.find('/', s1 + 1);
    if (s2 == std::string_view::npos) return false;
    std::string_view after_repo = rest.substr(s2);
    if (after_repo.size() <= 8 || after_repo.substr(0, 8) != "/issues/") return false;
    std::string_view num_sv = after_repo.substr(8);
    uint32_t num = 0;
    if (num_sv.find('/') != std::string_view::npos || !parse_uint32(num_sv, num)) return false;

    const Repo* repo = store.find_repo_const(rest.substr(0, s1), rest.substr(s1 + 1, s2 - s1 - 1));
    if (!repo) return false;
    const Issue* iss = repo->find_issue_const(num);
    if (!iss || iss->cached_http_response.empty()) return false;
    res.set_prebuilt(iss->cached_http_response);
    return true;
}

bool handle_rest(ForgeStore& store, const HttpRequest& req, HttpResponse& res) {
    std::string_view p = req.path;
    if (p.size() < 7 || p.substr(0, 7) != "/api/v3") return false;
    if (p.size() > 7 && p[7] != '/') return false;

    std::string_view sub = (p.size() == 7) ? std::string_view("/") : p.substr(7);

    // Auth check on every /api/v3 endpoint
    if (!store.check_auth(req.authorization)) {
        build_error_json(res, 401, "Requires authentication", store.next_request_id(), req.keep_alive);
        return true;
    }

    // Ultra-fast hot path: GET /api/v3/repos/{owner}/{repo}/issues/{number}
    if (req.method == "GET" && sub.size() > 7 && sub.substr(0, 7) == "/repos/") {
        std::string_view rest = sub.substr(7);
        size_t s1 = rest.find('/');
        if (s1 != std::string_view::npos) {
            size_t s2 = rest.find('/', s1 + 1);
            if (s2 != std::string_view::npos) {
                std::string_view after_repo = rest.substr(s2);
                if (after_repo.size() > 8 && after_repo.substr(0, 8) == "/issues/") {
                    std::string_view num_sv = after_repo.substr(8);
                    uint32_t num = 0;
                    if (num_sv.find('/') == std::string_view::npos && parse_uint32(num_sv, num)) {
                        std::string_view owner = rest.substr(0, s1);
                        std::string_view rname = rest.substr(s1 + 1, s2 - s1 - 1);
                        Repo* repo = store.find_repo(owner, rname);
                        if (!repo) {
                            build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                            return true;
                        }
                        Issue* iss = repo->find_issue(num);
                        if (!iss) {
                            build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                            return true;
                        }
                        if (req.keep_alive) {
                            res.set_prebuilt(store.get_or_build_issue_http(*repo, *iss));
                            return true;
                        }
                        std::string body;
                        ForgeStore::append_issue_json(*repo, *iss, body);
                        build_json_response(res, 200, body, store.next_request_id(), false);
                        return true;
                    }
                }
            }
        }
    }

    // Ultra-fast hot path: POST /api/v3/repos/{owner}/{repo}/issues
    if (req.method == "POST" && sub.size() > 14 && sub.substr(0, 7) == "/repos/" &&
        sub.substr(sub.size() - 7) == "/issues") {
        std::string_view mid = sub.substr(7, sub.size() - 14);
        size_t s1 = mid.find('/');
        if (s1 != std::string_view::npos && mid.find('/', s1 + 1) == std::string_view::npos &&
            mid.find('%') == std::string_view::npos) {
            std::string_view title_sv, body_sv;
            thread_local std::string title_buf, body_buf;
            if (fast_parse_issue_create(req.body, title_sv, body_sv, title_buf, body_buf)) {
                Repo* repo = store.find_repo(mid.substr(0, s1), mid.substr(s1 + 1));
                if (!repo) {
                    build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                    return true;
                }
                Issue* iss = store.create_issue_fast(*repo, title_sv, body_sv);
                // Single-pass zero-alloc HTTP 201 + JSON into res.owned_raw
                thread_local std::string jbuf;
                jbuf.clear();
                jbuf.reserve(128 + iss->title.size() + iss->body.size());
                ForgeStore::append_issue_json(*repo, *iss, jbuf);
                res.raw_ptr = nullptr;
                res.raw_len = 0;
                res.owned_raw.clear();
                res.owned_raw.reserve(96 + jbuf.size());
                if (req.keep_alive) {
                    res.owned_raw.append(
                        "HTTP/1.1 201 Created\r\n"
                        "Content-Type: application/json\r\n"
                        "X-GitHub-Request-Id: ", 75);
                    append_u64_hex(res.owned_raw, store.next_request_id());
                    res.owned_raw.append("\r\nContent-Length: ", 18);
                    append_u64_dec(res.owned_raw, jbuf.size());
                    res.owned_raw.append("\r\n\r\n", 4);
                    res.owned_raw.append(jbuf);
                } else {
                    build_json_response(res, 201, jbuf, store.next_request_id(), false);
                }
                return true;
            }
        }
    }

    // Root: GET /api/v3/ or /api/v3
    if (sub == "/" || sub.empty()) {
        if (req.method != "GET") {
            build_error_json(res, 405, "Method Not Allowed", store.next_request_id(), req.keep_alive);
            return true;
        }
        static constexpr std::string_view kRootBody =
            "{\"current_user_url\":\"/api/v3/user\","
            "\"repository_url\":\"/api/v3/repos/{owner}/{repo}\","
            "\"user_repositories_url\":\"/api/v3/user/repos\"}";
        build_json_response(res, 200, kRootBody, store.next_request_id(), req.keep_alive, "X-OAuth-Scopes: repo, read:org, user\r\n");
        return true;
    }

    // Meta: GET /api/v3/meta
    if (sub == "/meta") {
        if (req.method != "GET") {
            build_error_json(res, 405, "Method Not Allowed", store.next_request_id(), req.keep_alive);
            return true;
        }
        static constexpr std::string_view kMetaBody =
            "{\"verifiable_password_authentication\":false,\"installed_version\":\"3.14.0-cobalt\"}";
        build_json_response(res, 200, kMetaBody, store.next_request_id(), req.keep_alive);
        return true;
    }

    // User: GET /api/v3/user
    if (sub == "/user") {
        if (req.method != "GET") {
            build_error_json(res, 405, "Method Not Allowed", store.next_request_id(), req.keep_alive);
            return true;
        }
        std::string body = "{\"id\":1000,\"node_id\":\"U_1000\",\"login\":";
        append_json_escaped(body, store.viewer_login());
        body += ",\"type\":\"User\"}";
        build_json_response(res, 200, body, store.next_request_id(), req.keep_alive);
        return true;
    }

    // User repos: GET / POST /api/v3/user/repos
    if (sub == "/user/repos") {
        if (req.method == "POST") {
            JsonValue body;
            if (!parse_json_body(req, body, store, res)) return true;
            const auto* name_v = body.get("name");
            if (!name_v || !name_v->is_string() || name_v->s.empty()) {
                build_error_json(res, 422, "Validation Failed: name is required", store.next_request_id(), req.keep_alive);
                return true;
            }
            bool priv = body.get("private") ? body.get("private")->as_bool(false) : false;
            std::string desc = body.get("description") ? body.get("description")->as_string("") : "";
            std::string def_br = body.get("default_branch") ? body.get("default_branch")->as_string("main") : "main";
            Repo* repo = store.create_repo(name_v->s, priv, desc, def_br);
            if (!repo) {
                build_error_json(res, 422, "Repository creation failed: name already exists on this account", store.next_request_id(), req.keep_alive);
                return true;
            }
            std::string out;
            out.reserve(256);
            ForgeStore::append_repo_json(*repo, out);
            build_json_response(res, 201, out, store.next_request_id(), req.keep_alive);
            return true;
        }
        if (req.method == "GET") {
            int per_page = std::clamp(qparam_int(req.query, "per_page", 30), 1, 100);
            int page = std::max(1, qparam_int(req.query, "page", 1));
            const auto& all = store.list_repos();
            size_t total = all.size();
            size_t start = static_cast<size_t>(page - 1) * static_cast<size_t>(per_page);
            size_t end = std::min(total, start + static_cast<size_t>(per_page));
            std::string out = "[";
            for (size_t i = start; i < end; ++i) {
                if (i > start) out.push_back(',');
                ForgeStore::append_repo_json(*all[i], out);
            }
            out.push_back(']');

            std::string extra;
            if (end < total) {
                int last_page = static_cast<int>((total + static_cast<size_t>(per_page) - 1) / static_cast<size_t>(per_page));
                std::string origin = req.host.empty() ? "" : ("http://" + std::string(req.host));
                extra = "Link: <" + origin + "/api/v3/user/repos?per_page=" + std::to_string(per_page) +
                        "&page=" + std::to_string(page + 1) + ">; rel=\"next\", <" + origin +
                        "/api/v3/user/repos?per_page=" + std::to_string(per_page) +
                        "&page=" + std::to_string(last_page) + ">; rel=\"last\"\r\n";
            }
            build_json_response(res, 200, out, store.next_request_id(), req.keep_alive, extra);
            return true;
        }
        build_error_json(res, 405, "Method Not Allowed", store.next_request_id(), req.keep_alive);
        return true;
    }

    // Repo-scoped routes: /repos/{owner}/{repo}...
    std::vector<std::string_view> segs;
    split_segments(sub, segs);
    if (segs.size() < 3 || segs[0] != "repos") {
        build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
        return true;
    }

    std::string owner = url_decode(segs[1]);
    std::string repo_name = url_decode(segs[2]);

    // DELETE /repos/{owner}/{repo}
    if (segs.size() == 3 && req.method == "DELETE") {
        if (!store.delete_repo(owner, repo_name)) {
            build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
            return true;
        }
        build_http_response(res, 204, "application/json; charset=utf-8", "", store.next_request_id(), req.keep_alive);
        return true;
    }

    Repo* repo = store.find_repo(owner, repo_name);
    if (!repo) {
        build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
        return true;
    }

    // /repos/{owner}/{repo}
    if (segs.size() == 3) {
        if (req.method == "GET") {
            std::string out;
            ForgeStore::append_repo_json(*repo, out);
            build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
            return true;
        }
        if (req.method == "PATCH") {
            JsonValue body;
            if (!parse_json_body(req, body, store, res)) return true;
            if (const auto* d = body.get("description"); d && d->is_string()) repo->description = d->s;
            if (const auto* pr = body.get("private"); pr && pr->is_bool()) repo->is_private = pr->b;
            if (const auto* db = body.get("default_branch"); db && db->is_string() && !db->s.empty()) repo->default_branch = db->s;
            std::string out;
            ForgeStore::append_repo_json(*repo, out);
            build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
            return true;
        }
        build_error_json(res, 405, "Method Not Allowed", store.next_request_id(), req.keep_alive);
        return true;
    }

    std::string_view resource = segs[3];

    // /repos/{o}/{r}/branches[/{branch}]
    if (resource == "branches") {
        if (req.method != "GET") {
            build_error_json(res, 405, "Method Not Allowed", store.next_request_id(), req.keep_alive);
            return true;
        }
        if (segs.size() == 4) {
            std::string out = "[";
            bool first = true;
            for (const auto& [ref_name, oid] : repo->refs) {
                if (ref_name.size() > 11 && ref_name.substr(0, 11) == "refs/heads/") {
                    if (!first) out.push_back(',');
                    first = false;
                    out += "{\"name\":";
                    append_json_escaped(out, ref_name.substr(11));
                    out += ",\"commit\":{\"sha\":";
                    append_json_escaped(out, oid.hex());
                    out += "}}";
                }
            }
            out.push_back(']');
            build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
            return true;
        }
        std::string branch;
        for (size_t i = 4; i < segs.size(); ++i) {
            if (i > 4) branch.push_back('/');
            branch += url_decode(segs[i]);
        }
        auto it = repo->refs.find("refs/heads/" + branch);
        if (it == repo->refs.end()) {
            build_error_json(res, 404, "Branch not found", store.next_request_id(), req.keep_alive);
            return true;
        }
        std::string out = "{\"name\":";
        append_json_escaped(out, branch);
        out += ",\"commit\":{\"sha\":";
        append_json_escaped(out, it->second.hex());
        out += "}}";
        build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
        return true;
    }

    // /repos/{o}/{r}/git/refs[...] or /git/ref/...
    if (resource == "git" && segs.size() >= 5 && (segs[4] == "refs" || segs[4] == "ref")) {
        if (req.method == "POST" && segs.size() == 5 && segs[4] == "refs") {
            JsonValue body;
            if (!parse_json_body(req, body, store, res)) return true;
            std::string ref_name = body.get("ref") ? body.get("ref")->as_string("") : "";
            std::string sha_hex = body.get("sha") ? body.get("sha")->as_string("") : "";
            Oid oid;
            if (ref_name.empty() || !parse_oid(sha_hex, oid) || repo->objects.find(oid) == repo->objects.end()) {
                build_error_json(res, 422, "Validation Failed: invalid ref or sha", store.next_request_id(), req.keep_alive);
                return true;
            }
            if (repo->refs.find(ref_name) != repo->refs.end()) {
                build_error_json(res, 422, "Reference already exists", store.next_request_id(), req.keep_alive);
                return true;
            }
            repo->refs[ref_name] = oid;
            repo->ref_version++;
            std::string out = "{\"ref\":";
            append_json_escaped(out, ref_name);
            out += ",\"object\":{\"sha\":";
            append_json_escaped(out, oid.hex());
            out += ",\"type\":\"commit\"}}";
            build_json_response(res, 201, out, store.next_request_id(), req.keep_alive);
            return true;
        }
        if (req.method == "GET" && segs.size() >= 6) {
            std::string ref_tail;
            for (size_t i = 5; i < segs.size(); ++i) {
                if (i > 5) ref_tail.push_back('/');
                ref_tail += url_decode(segs[i]);
            }
            std::string full_ref = (ref_tail.substr(0, 5) == "refs/") ? ref_tail : ("refs/" + ref_tail);
            auto it = repo->refs.find(full_ref);
            if (it == repo->refs.end()) {
                build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                return true;
            }
            std::string out = "{\"ref\":";
            append_json_escaped(out, full_ref);
            out += ",\"object\":{\"sha\":";
            append_json_escaped(out, it->second.hex());
            out += ",\"type\":\"commit\"}}";
            build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
            return true;
        }
        build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
        return true;
    }

    // /repos/{o}/{r}/commits
    if (resource == "commits" && segs.size() == 4 && req.method == "GET") {
        std::string sha_q = url_decode(qparam(req.query, "sha"));
        Oid tip;
        if (!store.resolve_ref_oid(*repo, sha_q, tip)) {
            build_json_response(res, 200, "[]", store.next_request_id(), req.keep_alive);
            return true;
        }
        std::string out = "[";
        std::unordered_set<Oid, OidHash> visited;
        std::queue<Oid> q;
        q.push(tip);
        visited.insert(tip);
        bool first = true;
        int limit = std::clamp(qparam_int(req.query, "per_page", 100), 1, 500);
        int emitted = 0;
        while (!q.empty() && emitted < limit) {
            Oid cur = q.front();
            q.pop();
            auto it = repo->objects.find(cur);
            if (it == repo->objects.end() || it->second.type != ObjType::Commit) continue;
            store.parse_obj_meta(*repo, it->second);
            if (!first) out.push_back(',');
            first = false;
            std::string_view msg = ForgeStore::commit_message(*repo, it->second);
            if (!msg.empty() && msg.back() == '\n') msg.remove_suffix(1);
            out += "{\"sha\":";
            append_json_escaped(out, cur.hex());
            out += ",\"commit\":{\"message\":";
            append_json_escaped(out, msg);
            out += ",\"tree\":{\"sha\":";
            append_json_escaped(out, it->second.tree_oid.hex());
            out += "}}}";
            ++emitted;
            it->second.for_each_parent([&](const Oid& par) {
                if (visited.insert(par).second) q.push(par);
            });
        }
        out.push_back(']');
        build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
        return true;
    }

    // /repos/{o}/{r}/contents/{path...}
    if (resource == "contents") {
        std::string file_path;
        for (size_t i = 4; i < segs.size(); ++i) {
            if (i > 4) file_path.push_back('/');
            file_path += url_decode(segs[i]);
        }

        if (req.method == "GET") {
            std::string ref_q = url_decode(qparam(req.query, "ref"));
            Oid commit_oid;
            if (!store.resolve_ref_oid(*repo, ref_q, commit_oid)) {
                build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                return true;
            }
            auto cit = repo->objects.find(commit_oid);
            if (cit == repo->objects.end() || cit->second.type != ObjType::Commit) {
                build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                return true;
            }
            store.parse_obj_meta(*repo, cit->second);
            bool is_dir = false;
            Oid target_oid;
            if (!store.lookup_path_in_tree(*repo, cit->second.tree_oid, file_path, is_dir, target_oid)) {
                build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                return true;
            }
            if (is_dir) {
                auto tit = repo->objects.find(target_oid);
                if (tit == repo->objects.end() || tit->second.type != ObjType::Tree) {
                    build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                    return true;
                }
                auto entries = ForgeStore::parse_tree(repo->raw_data(tit->second), tit->second.raw_len);
                std::string out = "[";
                for (size_t i = 0; i < entries.size(); ++i) {
                    if (i > 0) out.push_back(',');
                    const auto& e = entries[i];
                    std::string entry_path = file_path.empty() ? e.name : (file_path + "/" + e.name);
                    bool d = (e.mode == "40000");
                    size_t sz = 0;
                    if (!d) {
                        if (auto bit = repo->objects.find(e.oid); bit != repo->objects.end()) sz = bit->second.raw_len;
                    }
                    out += "{\"type\":";
                    out += d ? "\"dir\"" : "\"file\"";
                    out += ",\"name\":";
                    append_json_escaped(out, e.name);
                    out += ",\"path\":";
                    append_json_escaped(out, entry_path);
                    out += ",\"sha\":";
                    append_json_escaped(out, e.oid.hex());
                    out += ",\"size\":";
                    out += std::to_string(sz);
                    out += "}";
                }
                out.push_back(']');
                build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
                return true;
            } else {
                auto bit = repo->objects.find(target_oid);
                if (bit == repo->objects.end() || bit->second.type != ObjType::Blob) {
                    build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                    return true;
                }
                size_t slash = file_path.rfind('/');
                std::string name = (slash == std::string::npos) ? file_path : file_path.substr(slash + 1);
                std::string b64 = base64_encode(repo->raw_data(bit->second), bit->second.raw_len);
                std::string out = "{\"type\":\"file\",\"encoding\":\"base64\",\"name\":";
                append_json_escaped(out, name);
                out += ",\"path\":";
                append_json_escaped(out, file_path);
                out += ",\"sha\":";
                append_json_escaped(out, target_oid.hex());
                out += ",\"size\":";
                out += std::to_string(bit->second.raw_len);
                out += ",\"content\":";
                append_json_escaped(out, b64);
                out += "}";
                build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
                return true;
            }
        }

        if (req.method == "PUT") {
            JsonValue body;
            if (!parse_json_body(req, body, store, res)) return true;
            const auto* msg_v = body.get("message");
            const auto* content_v = body.get("content");
            if (!msg_v || !msg_v->is_string() || !content_v || !content_v->is_string()) {
                build_error_json(res, 422, "Validation Failed: message and content required", store.next_request_id(), req.keep_alive);
                return true;
            }
            std::vector<uint8_t> raw_bytes;
            if (!base64_decode(content_v->s, raw_bytes)) {
                build_error_json(res, 422, "Validation Failed: content is not valid base64", store.next_request_id(), req.keep_alive);
                return true;
            }
            std::string branch = body.get("branch") ? body.get("branch")->as_string("") : "";
            std::string sha = body.get("sha") ? body.get("sha")->as_string("") : "";

            Oid blob_oid{}, commit_oid{};
            bool created = false;
            int status = 201;
            std::string err;
            if (!store.put_file_content(*repo, file_path, raw_bytes, msg_v->s, branch, sha, blob_oid, commit_oid, created, status, err)) {
                build_error_json(res, status, err, store.next_request_id(), req.keep_alive);
                return true;
            }
            size_t slash = file_path.rfind('/');
            std::string name = (slash == std::string::npos) ? file_path : file_path.substr(slash + 1);
            std::string out = "{\"content\":{\"name\":";
            append_json_escaped(out, name);
            out += ",\"path\":";
            append_json_escaped(out, file_path);
            out += ",\"sha\":";
            append_json_escaped(out, blob_oid.hex());
            out += ",\"size\":";
            out += std::to_string(raw_bytes.size());
            out += ",\"type\":\"file\",\"encoding\":\"base64\"},\"commit\":{\"sha\":";
            append_json_escaped(out, commit_oid.hex());
            out += ",\"message\":";
            append_json_escaped(out, msg_v->s);
            out += "}}";
            build_json_response(res, status, out, store.next_request_id(), req.keep_alive);
            return true;
        }

        if (req.method == "DELETE") {
            JsonValue body;
            if (!parse_json_body(req, body, store, res)) return true;
            std::string msg = body.get("message") ? body.get("message")->as_string("delete file") : "delete file";
            std::string branch = body.get("branch") ? body.get("branch")->as_string("") : "";
            std::string sha = body.get("sha") ? body.get("sha")->as_string("") : "";
            Oid commit_oid{};
            int status = 200;
            std::string err;
            if (!store.delete_file_content(*repo, file_path, msg, branch, sha, commit_oid, status, err)) {
                build_error_json(res, status, err, store.next_request_id(), req.keep_alive);
                return true;
            }
            std::string out = "{\"content\":null,\"commit\":{\"sha\":";
            append_json_escaped(out, commit_oid.hex());
            out += ",\"message\":";
            append_json_escaped(out, msg);
            out += "}}";
            build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
            return true;
        }
        build_error_json(res, 405, "Method Not Allowed", store.next_request_id(), req.keep_alive);
        return true;
    }

    // /repos/{o}/{r}/labels
    if (resource == "labels" && segs.size() == 4) {
        if (req.method == "POST") {
            JsonValue body;
            if (!parse_json_body(req, body, store, res)) return true;
            const auto* name_v = body.get("name");
            if (!name_v || !name_v->is_string() || name_v->s.empty()) {
                build_error_json(res, 422, "Validation Failed: name is required", store.next_request_id(), req.keep_alive);
                return true;
            }
            std::string color = body.get("color") ? body.get("color")->as_string("ededed") : "ededed";
            std::string desc = body.get("description") ? body.get("description")->as_string("") : "";
            Label* lbl = store.create_label(*repo, name_v->s, color, desc);
            std::string out = "{\"id\":";
            out += std::to_string(lbl->id);
            out += ",\"name\":";
            append_json_escaped(out, lbl->name);
            out += ",\"color\":";
            append_json_escaped(out, lbl->color);
            out += ",\"description\":";
            append_json_escaped(out, lbl->description);
            out += "}";
            build_json_response(res, 201, out, store.next_request_id(), req.keep_alive);
            return true;
        }
        if (req.method == "GET") {
            std::string out = "[";
            bool first = true;
            for (const auto& [_, lbl] : repo->labels) {
                if (!first) out.push_back(',');
                first = false;
                out += "{\"id\":";
                out += std::to_string(lbl.id);
                out += ",\"name\":";
                append_json_escaped(out, lbl.name);
                out += ",\"color\":";
                append_json_escaped(out, lbl.color);
                out += "}";
            }
            out.push_back(']');
            build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
            return true;
        }
    }

    // /repos/{o}/{r}/issues[/{n}[/comments]]
    if (resource == "issues") {
        if (segs.size() == 4) {
            if (req.method == "POST") {
                JsonValue body;
                if (!parse_json_body(req, body, store, res)) return true;
                const auto* title_v = body.get("title");
                if (!title_v || !title_v->is_string() || title_v->s.empty()) {
                    build_error_json(res, 422, "Validation Failed: title is required", store.next_request_id(), req.keep_alive);
                    return true;
                }
                std::string ibody = body.get("body") ? body.get("body")->as_string("") : "";
                std::vector<std::string> labels;
                if (const auto* lv = body.get("labels"); lv && lv->is_array()) {
                    for (const auto& elem : lv->arr) {
                        if (elem.is_string()) labels.push_back(elem.s);
                        else if (elem.is_object() && elem.get("name")) labels.push_back(elem.get("name")->as_string(""));
                    }
                }
                std::string err;
                Issue* iss = store.create_issue(*repo, title_v->s, std::move(ibody), labels, err);
                if (!iss) {
                    build_error_json(res, 422, err, store.next_request_id(), req.keep_alive);
                    return true;
                }
                std::string out;
                out.reserve(256 + iss->title.size() + iss->body.size());
                ForgeStore::append_issue_json(*repo, *iss, out);
                build_json_response(res, 201, out, store.next_request_id(), req.keep_alive);
                return true;
            }
            if (req.method == "GET") {
                std::string_view state = qparam(req.query, "state");
                if (state.empty()) state = "open";
                std::string_view direction = qparam(req.query, "direction");
                bool asc = (direction == "asc");
                int per_page = std::clamp(qparam_int(req.query, "per_page", 30), 1, 100);
                int page = std::max(1, qparam_int(req.query, "page", 1));

                std::vector<const Issue*> list;
                list.reserve(repo->issues.size());
                for (const auto& iss : repo->issues) {
                    if (state == "open" && iss.closed) continue;
                    if (state == "closed" && !iss.closed) continue;
                    list.push_back(&iss);
                }
                if (asc) {
                    std::sort(list.begin(), list.end(), [](const Issue* a, const Issue* b) {
                        return a->created_seq < b->created_seq;
                    });
                } else {
                    std::sort(list.begin(), list.end(), [](const Issue* a, const Issue* b) {
                        return a->created_seq > b->created_seq;
                    });
                }
                size_t start = static_cast<size_t>(page - 1) * static_cast<size_t>(per_page);
                size_t end = std::min(list.size(), start + static_cast<size_t>(per_page));
                std::string out = "[";
                for (size_t i = start; i < end; ++i) {
                    if (i > start) out.push_back(',');
                    ForgeStore::append_issue_json(*repo, *list[i], out);
                }
                out.push_back(']');
                build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
                return true;
            }
        }
        if (segs.size() >= 5) {
            uint32_t num = 0;
            if (!parse_uint32(segs[4], num)) {
                build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                return true;
            }
            Issue* iss_ptr = repo->find_issue(num);
            if (!iss_ptr) {
                build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                return true;
            }
            Issue& iss = *iss_ptr;
            if (segs.size() == 5) {
                if (req.method == "GET") {
                    if (req.keep_alive) {
                        res.set_prebuilt(store.get_or_build_issue_http(*repo, iss));
                        return true;
                    }
                    std::string out;
                    ForgeStore::append_issue_json(*repo, iss, out);
                    build_json_response(res, 200, out, store.next_request_id(), false);
                    return true;
                }
                if (req.method == "PATCH") {
                    JsonValue body;
                    if (!parse_json_body(req, body, store, res)) return true;
                    if (const auto* st = body.get("state"); st && st->is_string()) {
                        if (st->s == "closed") iss.closed = true;
                        else if (st->s == "open") iss.closed = false;
                    }
                    if (const auto* t = body.get("title"); t && t->is_string()) iss.title = t->s;
                    if (const auto* b = body.get("body"); b && b->is_string()) iss.body = b->s;
                    if (const auto* lv = body.get("labels"); lv && lv->is_array()) {
                        std::vector<std::string> next_labels;
                        for (const auto& elem : lv->arr) {
                            std::string name = elem.is_string() ? elem.s : (elem.get("name") ? elem.get("name")->as_string("") : "");
                            if (repo->labels.find(name) == repo->labels.end()) {
                                build_error_json(res, 422, "Validation Failed: unknown label", store.next_request_id(), req.keep_alive);
                                return true;
                            }
                            next_labels.push_back(std::move(name));
                        }
                        iss.labels = std::move(next_labels);
                    }
                    iss.updated_epoch = store.next_commit_epoch();
                    iss.cached_http_response.clear();
                    std::string out;
                    ForgeStore::append_issue_json(*repo, iss, out);
                    build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
                    return true;
                }
            }
            if (segs.size() == 6 && segs[5] == "comments") {
                if (req.method == "POST") {
                    JsonValue body;
                    if (!parse_json_body(req, body, store, res)) return true;
                    const auto* b = body.get("body");
                    if (!b || !b->is_string()) {
                        build_error_json(res, 422, "Validation Failed: body is required", store.next_request_id(), req.keep_alive);
                        return true;
                    }
                    Comment* c = store.add_comment(*repo, iss, b->s);
                    std::string out = "{\"id\":";
                    out += std::to_string(c->id);
                    out += ",\"node_id\":";
                    append_json_escaped(out, c->node_id);
                    out += ",\"body\":";
                    append_json_escaped(out, c->body);
                    out += ",\"user\":{\"login\":";
                    append_json_escaped(out, c->author_login);
                    out += "},\"created_at\":";
                    append_json_escaped(out, ForgeStore::format_iso8601(c->created_epoch));
                    out += "}";
                    build_json_response(res, 201, out, store.next_request_id(), req.keep_alive);
                    return true;
                }
                if (req.method == "GET") {
                    std::string out = "[";
                    for (size_t i = 0; i < iss.comments.size(); ++i) {
                        if (i > 0) out.push_back(',');
                        const auto& c = iss.comments[i];
                        out += "{\"id\":";
                        out += std::to_string(c.id);
                        out += ",\"node_id\":";
                        append_json_escaped(out, c.node_id);
                        out += ",\"body\":";
                        append_json_escaped(out, c.body);
                        out += ",\"user\":{\"login\":";
                        append_json_escaped(out, c.author_login);
                        out += "},\"created_at\":";
                        append_json_escaped(out, ForgeStore::format_iso8601(c.created_epoch));
                        out += "}";
                    }
                    out.push_back(']');
                    build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
                    return true;
                }
            }
        }
    }

    // /repos/{o}/{r}/pulls[/{n}[/files|/merge]]
    if (resource == "pulls") {
        if (segs.size() == 4) {
            if (req.method == "POST") {
                JsonValue body;
                if (!parse_json_body(req, body, store, res)) return true;
                std::string title = body.get("title") ? body.get("title")->as_string("") : "";
                std::string pbody = body.get("body") ? body.get("body")->as_string("") : "";
                std::string head = body.get("head") ? body.get("head")->as_string("") : "";
                std::string base = body.get("base") ? body.get("base")->as_string(repo->default_branch) : repo->default_branch;
                if (title.empty() || head.empty()) {
                    build_error_json(res, 422, "Validation Failed: title and head are required", store.next_request_id(), req.keep_alive);
                    return true;
                }
                std::string err;
                PullRequest* pr = store.create_pull(*repo, std::move(title), std::move(pbody), head, base, err);
                if (!pr) {
                    build_error_json(res, 422, err, store.next_request_id(), req.keep_alive);
                    return true;
                }
                std::string out;
                ForgeStore::append_pull_json(*repo, *pr, out);
                build_json_response(res, 201, out, store.next_request_id(), req.keep_alive);
                return true;
            }
            if (req.method == "GET") {
                std::string_view state = qparam(req.query, "state");
                if (state.empty()) state = "open";
                int per_page = std::clamp(qparam_int(req.query, "per_page", 30), 1, 100);
                int page = std::max(1, qparam_int(req.query, "page", 1));
                std::vector<const PullRequest*> list;
                for (const auto& up : repo->pulls) {
                    if (state == "open" && up->closed) continue;
                    if (state == "closed" && !up->closed) continue;
                    list.push_back(up.get());
                }
                std::sort(list.begin(), list.end(), [](const PullRequest* a, const PullRequest* b) {
                    return a->created_seq > b->created_seq;
                });
                size_t start = static_cast<size_t>(page - 1) * static_cast<size_t>(per_page);
                size_t end = std::min(list.size(), start + static_cast<size_t>(per_page));
                std::string out = "[";
                for (size_t i = start; i < end; ++i) {
                    if (i > start) out.push_back(',');
                    ForgeStore::append_pull_json(*repo, *list[i], out);
                }
                out.push_back(']');
                build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
                return true;
            }
        }
        if (segs.size() >= 5) {
            uint32_t num = 0;
            if (!parse_uint32(segs[4], num)) {
                build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                return true;
            }
            auto it = repo->pull_by_number.find(num);
            if (it == repo->pull_by_number.end()) {
                build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
                return true;
            }
            PullRequest& pr = *it->second;
            if (segs.size() == 5 && req.method == "GET") {
                std::string out;
                ForgeStore::append_pull_json(*repo, pr, out);
                build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
                return true;
            }
            if (segs.size() == 6 && segs[5] == "files" && req.method == "GET") {
                auto diffs = store.diff_pull(*repo, pr);
                std::string out = "[";
                for (size_t i = 0; i < diffs.size(); ++i) {
                    if (i > 0) out.push_back(',');
                    const auto& d = diffs[i];
                    out += "{\"filename\":";
                    append_json_escaped(out, d.filename);
                    out += ",\"status\":";
                    append_json_escaped(out, d.status);
                    out += ",\"additions\":";
                    out += std::to_string(d.additions);
                    out += ",\"deletions\":";
                    out += std::to_string(d.deletions);
                    out += ",\"changes\":";
                    out += std::to_string(d.changes);
                    out += ",\"sha\":";
                    append_json_escaped(out, d.sha.hex());
                    out += "}";
                }
                out.push_back(']');
                build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
                return true;
            }
            if (segs.size() == 6 && segs[5] == "merge" && req.method == "PUT") {
                JsonValue body;
                if (!parse_json_body(req, body, store, res)) return true;
                std::string method = body.get("merge_method") ? body.get("merge_method")->as_string("squash") : "squash";
                Oid merge_sha{};
                std::string err;
                int status = 200;
                if (!store.merge_pull(*repo, pr, method, merge_sha, err, status)) {
                    build_error_json(res, status, err, store.next_request_id(), req.keep_alive);
                    return true;
                }
                std::string out = "{\"sha\":";
                append_json_escaped(out, merge_sha.hex());
                out += ",\"merged\":true,\"message\":\"Pull Request successfully merged\"}";
                build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
                return true;
            }
        }
    }

    build_error_json(res, 404, "Not Found", store.next_request_id(), req.keep_alive);
    return true;
}

} // namespace forge
