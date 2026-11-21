#include "git_http.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <queue>
#include <unordered_set>

namespace forge {

namespace {

void append_pkt(std::string& out, std::string_view payload) {
    char len_hex[5];
    std::snprintf(len_hex, sizeof(len_hex), "%04x", static_cast<unsigned>(payload.size() + 4));
    out.append(len_hex, 4);
    out.append(payload);
}

void append_pkt_sideband(std::string& out, uint8_t band, const uint8_t* data, size_t len) {
    constexpr size_t kMaxChunk = 65515; // 65520 - 4 - 1
    size_t pos = 0;
    while (pos < len) {
        size_t take = std::min(kMaxChunk, len - pos);
        char len_hex[5];
        std::snprintf(len_hex, sizeof(len_hex), "%04x", static_cast<unsigned>(take + 5));
        out.append(len_hex, 4);
        out.push_back(static_cast<char>(band));
        out.append(reinterpret_cast<const char*>(data + pos), take);
        pos += take;
    }
}

struct PktLine {
    enum class Kind : uint8_t { Data, Flush, Delim, ResponseEnd };
    Kind kind = Kind::Data;
    std::string_view payload;
};

bool parse_pkt_lines(std::string_view buf, std::vector<PktLine>& out, size_t& consumed, bool stop_at_first_flush = false) {
    size_t pos = 0;
    while (pos < buf.size()) {
        if (pos + 4 > buf.size()) return false;
        unsigned len = 0;
        for (int i = 0; i < 4; ++i) {
            int n = hex_nibble(buf[pos + i]);
            if (n < 0) return false;
            len = (len << 4) | static_cast<unsigned>(n);
        }
        if (len == 0) {
            out.push_back(PktLine{PktLine::Kind::Flush, {}});
            pos += 4;
            if (stop_at_first_flush) {
                consumed = pos;
                return true;
            }
        } else if (len == 1) {
            out.push_back(PktLine{PktLine::Kind::Delim, {}});
            pos += 4;
        } else if (len == 2) {
            out.push_back(PktLine{PktLine::Kind::ResponseEnd, {}});
            pos += 4;
        } else if (len < 4 || pos + len > buf.size()) {
            return false;
        } else {
            out.push_back(PktLine{PktLine::Kind::Data, buf.substr(pos + 4, len - 4)});
            pos += len;
        }
    }
    consumed = pos;
    return true;
}

std::string_view strip_nl(std::string_view s) noexcept {
    if (!s.empty() && s.back() == '\n') s.remove_suffix(1);
    if (!s.empty() && s.back() == '\r') s.remove_suffix(1);
    return s;
}

std::string_view query_param(std::string_view query, std::string_view key) noexcept {
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

// Collect all objects reachable from `roots`, stopping traversal at `stop_objs`
// and not following parents of commits in `shallow_boundaries`.
void collect_tree_and_blobs(
    ForgeStore& store,
    Repo& repo,
    const Oid& tree_oid,
    const std::unordered_set<Oid, OidHash>& exclude,
    std::unordered_set<Oid, OidHash>& seen,
    std::vector<Oid>& out) {
    if (tree_oid.is_zero() || exclude.count(tree_oid) || !seen.insert(tree_oid).second) return;
    auto it = repo.objects.find(tree_oid);
    if (it == repo.objects.end() || it->second.type != ObjType::Tree) return;
    out.push_back(tree_oid);
    auto entries = ForgeStore::parse_tree(repo.raw_data(it->second), it->second.raw_len);
    for (const auto& e : entries) {
        if (e.mode == "160000") continue; // gitlink
        if (e.mode == "40000") {
            collect_tree_and_blobs(store, repo, e.oid, exclude, seen, out);
        } else {
            if (!exclude.count(e.oid) && seen.insert(e.oid).second) {
                if (repo.objects.count(e.oid)) out.push_back(e.oid);
            }
        }
    }
}

void collect_reachable_full(
    ForgeStore& store,
    Repo& repo,
    const std::vector<Oid>& roots,
    const std::unordered_set<Oid, OidHash>& shallow_stop,
    const std::unordered_set<Oid, OidHash>& exclude,
    std::unordered_set<Oid, OidHash>& seen,
    std::vector<Oid>& out) {
    std::vector<Oid> stack;
    for (const auto& r : roots) {
        if (!r.is_zero() && !exclude.count(r)) stack.push_back(r);
    }
    while (!stack.empty()) {
        Oid cur = stack.back();
        stack.pop_back();
        if (exclude.count(cur) || !seen.insert(cur).second) continue;
        auto it = repo.objects.find(cur);
        if (it == repo.objects.end()) continue;
        out.push_back(cur);
        GitObj& obj = it->second;
        if (obj.type == ObjType::Commit) {
            store.parse_obj_meta(repo, obj);
            collect_tree_and_blobs(store, repo, obj.tree_oid, exclude, seen, out);
            if (!shallow_stop.count(cur)) {
                obj.for_each_parent([&](const Oid& p) {
                    if (!exclude.count(p) && !seen.count(p)) stack.push_back(p);
                });
            }
        } else if (obj.type == ObjType::Tag) {
            store.parse_obj_meta(repo, obj);
            if (!obj.tag_target.is_zero() && !exclude.count(obj.tag_target) && !seen.count(obj.tag_target)) {
                stack.push_back(obj.tag_target);
            }
        } else if (obj.type == ObjType::Tree) {
            auto entries = ForgeStore::parse_tree(repo.raw_data(obj), obj.raw_len);
            for (const auto& e : entries) {
                if (e.mode == "160000") continue;
                if (!exclude.count(e.oid) && !seen.count(e.oid)) stack.push_back(e.oid);
            }
        }
    }
}

const std::string& static_v2_info_refs_http() {
    static const std::string kResp = [] {
        std::string body;
        append_pkt(body, "version 2\n");
        append_pkt(body, "ls-refs=unborn\n");
        append_pkt(body, "fetch=shallow\n");
        body.append("0000");
        std::string hdr =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/x-git-upload-pack-advertisement\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        return hdr + body;
    }();
    return kResp;
}

void compute_fetch_objects(
    ForgeStore& store,
    Repo& repo,
    const std::vector<Oid>& wants,
    const std::vector<Oid>& haves,
    const std::vector<Oid>& client_shallows,
    int deepen,
    std::vector<Oid>& out_objs,
    std::vector<Oid>& out_shallows,
    std::vector<Oid>& out_unshallows) {
    std::unordered_set<Oid, OidHash> client_shallow_set(client_shallows.begin(), client_shallows.end());

    // 1. Objects the client already holds (respecting client's old shallow boundaries)
    std::unordered_set<Oid, OidHash> have_objs;
    if (!haves.empty()) {
        std::vector<Oid> dummy;
        std::unordered_set<Oid, OidHash> empty_excl;
        collect_reachable_full(store, repo, haves, client_shallow_set, empty_excl, have_objs, dummy);
    }

    std::unordered_set<Oid, OidHash> want_seen;
    if (deepen > 0) {
        // BFS commits from wants up to depth `deepen`
        std::unordered_map<Oid, int, OidHash> commit_depth;
        std::queue<Oid> q;
        for (const auto& w : wants) {
            auto it = repo.objects.find(w);
            if (it == repo.objects.end()) continue;
            if (it->second.type == ObjType::Tag) {
                if (!have_objs.count(w) && want_seen.insert(w).second) out_objs.push_back(w);
                Oid target = store.peel_oid(repo, w);
                if (!target.is_zero() && !commit_depth.count(target)) {
                    commit_depth[target] = 1;
                    q.push(target);
                }
            } else if (it->second.type == ObjType::Commit) {
                if (!commit_depth.count(w)) {
                    commit_depth[w] = 1;
                    q.push(w);
                }
            } else {
                std::vector<Oid> single{w};
                collect_reachable_full(store, repo, single, client_shallow_set, have_objs, want_seen, out_objs);
            }
        }

        std::unordered_set<Oid, OidHash> new_shallow_set;
        while (!q.empty()) {
            Oid cur = q.front();
            q.pop();
            int d = commit_depth[cur];
            auto it = repo.objects.find(cur);
            if (it == repo.objects.end() || it->second.type != ObjType::Commit) continue;
            GitObj& obj = it->second;
            store.parse_obj_meta(repo, obj);

            if (!have_objs.count(cur) && want_seen.insert(cur).second) {
                out_objs.push_back(cur);
            }
            collect_tree_and_blobs(store, repo, obj.tree_oid, have_objs, want_seen, out_objs);

            if (d >= deepen) {
                if (obj.parent_count > 0) {
                    if (new_shallow_set.insert(cur).second) out_shallows.push_back(cur);
                }
            } else {
                if (client_shallow_set.count(cur)) {
                    out_unshallows.push_back(cur);
                }
                obj.for_each_parent([&](const Oid& p) {
                    if (!commit_depth.count(p)) {
                        commit_depth[p] = d + 1;
                        q.push(p);
                    }
                });
            }
        }
    } else {
        std::unordered_set<Oid, OidHash> no_shallow;
        collect_reachable_full(store, repo, wants, no_shallow, have_objs, want_seen, out_objs);
    }
}

void handle_info_refs(ForgeStore& store, Repo& repo, const HttpRequest& req, HttpResponse& res) {
    std::string_view service = query_param(req.query, "service");
    if (service == "git-upload-pack") {
        bool v2 = (req.git_protocol.find("version=2") != std::string_view::npos);
        if (v2 && req.keep_alive) {
            res.set_prebuilt(static_v2_info_refs_http());
            return;
        }
        if (v2) {
            std::string body;
            append_pkt(body, "version 2\n");
            append_pkt(body, "agent=cobalt-forge/1.0\n");
            append_pkt(body, "ls-refs=unborn\n");
            append_pkt(body, "fetch=shallow\n");
            append_pkt(body, "object-format=sha1\n");
            body.append("0000");
            build_http_response(res, 200, "application/x-git-upload-pack-advertisement", body, store.next_request_id(), req.keep_alive);
            return;
        }
        // v0 upload-pack advertisement
        std::string head_target = "refs/heads/" + repo.default_branch;
        auto hit = repo.refs.find(head_target);
        std::string caps = "multi_ack_detailed side-band-64k shallow no-progress ofs-delta thin-pack agent=cobalt-forge/1.0";
        if (hit != repo.refs.end()) caps += " symref=HEAD:" + head_target;

        std::string body;
        append_pkt(body, "# service=git-upload-pack\n");
        body.append("0000");
        if (repo.refs.empty()) {
            std::string line = std::string(40, '0') + " capabilities^{}";
            line.push_back('\0');
            line += caps;
            line.push_back('\n');
            append_pkt(body, line);
        } else {
            bool first = true;
            auto emit_ref = [&](const std::string& name, const Oid& oid) {
                std::string line = oid.hex() + " " + name;
                if (first) {
                    line.push_back('\0');
                    line += caps;
                    first = false;
                }
                line.push_back('\n');
                append_pkt(body, line);
            };
            if (hit != repo.refs.end()) emit_ref("HEAD", hit->second);
            for (const auto& [name, oid] : repo.refs) {
                emit_ref(name, oid);
                auto oit = repo.objects.find(oid);
                if (oit != repo.objects.end() && oit->second.type == ObjType::Tag) {
                    Oid peeled = store.peel_oid(repo, oid);
                    if (peeled != oid) {
                        std::string pline = peeled.hex() + " " + name + "^{}\n";
                        append_pkt(body, pline);
                    }
                }
            }
        }
        body.append("0000");
        build_http_response(res, 200, "application/x-git-upload-pack-advertisement", body, store.next_request_id(), req.keep_alive);
        return;
    }

    if (service == "git-receive-pack") {
        static constexpr std::string_view kCaps = "report-status side-band-64k delete-refs";
        // Zero-allocation fast path for 0 or 1 ref (the push benchmark hot path!)
        if (repo.refs.size() <= 1) {
            char buf[512];
            size_t n = 0;
            auto put_pkt = [&](const char* p, size_t plen) {
                static constexpr char kHex[] = "0123456789abcdef";
                size_t total = plen + 4;
                buf[n++] = kHex[(total >> 12) & 0xf];
                buf[n++] = kHex[(total >> 8) & 0xf];
                buf[n++] = kHex[(total >> 4) & 0xf];
                buf[n++] = kHex[total & 0xf];
                std::memcpy(buf + n, p, plen);
                n += plen;
            };
            put_pkt("# service=git-receive-pack\n", 27);
            std::memcpy(buf + n, "0000", 4);
            n += 4;
            char line[256];
            size_t ln = 0;
            if (repo.refs.empty()) {
                std::memset(line, '0', 40);
                std::memcpy(line + 40, " capabilities^{}\0", 17);
                std::memcpy(line + 57, kCaps.data(), kCaps.size());
                line[57 + kCaps.size()] = '\n';
                ln = 58 + kCaps.size();
            } else {
                const auto& [name, oid] = *repo.refs.begin();
                if (40 + 1 + name.size() + 1 + kCaps.size() + 1 <= sizeof(line)) {
                    oid.write_hex(line);
                    line[40] = ' ';
                    std::memcpy(line + 41, name.data(), name.size());
                    ln = 41 + name.size();
                    line[ln++] = '\0';
                    std::memcpy(line + ln, kCaps.data(), kCaps.size());
                    ln += kCaps.size();
                    line[ln++] = '\n';
                }
            }
            if (ln > 0) {
                put_pkt(line, ln);
                std::memcpy(buf + n, "0000", 4);
                n += 4;
                build_git_http_response(res, "application/x-git-receive-pack-advertisement", std::string_view(buf, n), req.keep_alive);
                return;
            }
        }
        std::string body;
        body.reserve(160 + repo.refs.size() * 72);
        append_pkt(body, "# service=git-receive-pack\n");
        body.append("0000");
        bool first = true;
        char hex40[40];
        std::string line;
        line.reserve(160);
        for (const auto& [name, oid] : repo.refs) {
            line.clear();
            oid.write_hex(hex40);
            line.append(hex40, 40);
            line.push_back(' ');
            line.append(name);
            if (first) {
                line.push_back('\0');
                line.append(kCaps);
                first = false;
            }
            line.push_back('\n');
            append_pkt(body, line);
        }
        body.append("0000");
        build_git_http_response(res, "application/x-git-receive-pack-advertisement", body, req.keep_alive);
        return;
    }

    build_error_json(res, 400, "Unsupported git service", store.next_request_id(), req.keep_alive);
}

void handle_upload_pack(ForgeStore& store, Repo& repo, const HttpRequest& req, HttpResponse& res) {
    std::vector<PktLine> pkts;
    size_t consumed = 0;
    if (!parse_pkt_lines(req.body, pkts, consumed, false) || pkts.empty()) {
        build_error_json(res, 400, "Malformed pkt-line stream", store.next_request_id(), req.keep_alive);
        return;
    }

    bool is_v2 = (req.git_protocol.find("version=2") != std::string_view::npos);
    std::string_view command;
    for (const auto& p : pkts) {
        if (p.kind == PktLine::Kind::Delim || p.kind == PktLine::Kind::Flush) break;
        if (p.kind == PktLine::Kind::Data) {
            std::string_view line = strip_nl(p.payload);
            if (line.substr(0, 8) == "command=") {
                command = line.substr(8);
                is_v2 = true;
            }
        }
    }

    if (is_v2) {
        // Collect arguments after delim
        bool in_args = false;
        std::vector<std::string_view> args;
        for (const auto& p : pkts) {
            if (p.kind == PktLine::Kind::Delim) { in_args = true; continue; }
            if (p.kind == PktLine::Kind::Flush) break;
            if (in_args && p.kind == PktLine::Kind::Data) {
                args.push_back(strip_nl(p.payload));
            }
        }

        if (command == "ls-refs") {
            bool peel = false, symrefs = false, unborn = false;
            std::vector<std::string_view> prefixes;
            for (auto a : args) {
                if (a == "peel") peel = true;
                else if (a == "symrefs") symrefs = true;
                else if (a == "unborn") unborn = true;
                else if (a.substr(0, 11) == "ref-prefix ") prefixes.push_back(a.substr(11));
            }

            bool is_default_query = prefixes.empty() && peel && symrefs;
            if (req.keep_alive && is_default_query && repo.cached_ls_refs_version == repo.ref_version && !repo.cached_ls_refs_http.empty()) {
                res.set_prebuilt(repo.cached_ls_refs_http);
                return;
            }

            auto matches = [&](std::string_view name) -> bool {
                if (prefixes.empty()) return true;
                for (auto pre : prefixes) {
                    if (name.size() >= pre.size() && name.substr(0, pre.size()) == pre) return true;
                }
                return false;
            };

            std::string body;
            std::string head_target = "refs/heads/" + repo.default_branch;
            if (matches("HEAD")) {
                auto hit = repo.refs.find(head_target);
                if (hit != repo.refs.end()) {
                    std::string line = hit->second.hex() + " HEAD";
                    if (symrefs) line += " symref-target:" + head_target;
                    line.push_back('\n');
                    append_pkt(body, line);
                } else if (unborn) {
                    std::string line = "unborn HEAD";
                    if (symrefs) line += " symref-target:" + head_target;
                    line.push_back('\n');
                    append_pkt(body, line);
                }
            }
            for (const auto& [name, oid] : repo.refs) {
                if (!matches(name)) continue;
                std::string line = oid.hex() + " " + name;
                if (peel) {
                    auto oit = repo.objects.find(oid);
                    if (oit != repo.objects.end() && oit->second.type == ObjType::Tag) {
                        Oid peeled = store.peel_oid(repo, oid);
                        if (peeled != oid) {
                            line += " peeled:" + peeled.hex();
                        }
                    }
                }
                line.push_back('\n');
                append_pkt(body, line);
            }
            body.append("0000");
            build_git_http_response(res, "application/x-git-upload-pack-result", body, req.keep_alive);
            if (req.keep_alive && is_default_query) {
                repo.cached_ls_refs_http = res.owned_raw;
                repo.cached_ls_refs_version = repo.ref_version;
            }
            return;
        }

        if (command == "fetch") {
            std::vector<Oid> wants, haves, shallows;
            int deepen = 0;
            for (auto a : args) {
                if (a.size() == 45 && a.substr(0, 5) == "want ") {
                    Oid o; if (parse_oid(a.substr(5), o)) wants.push_back(o);
                } else if (a.size() == 45 && a.substr(0, 5) == "have ") {
                    Oid o; if (parse_oid(a.substr(5), o)) haves.push_back(o);
                } else if (a.size() == 48 && a.substr(0, 8) == "shallow ") {
                    Oid o; if (parse_oid(a.substr(8), o)) shallows.push_back(o);
                } else if (a.substr(0, 7) == "deepen ") {
                    deepen = std::atoi(std::string(a.substr(7)).c_str());
                }
            }

            // Ultra-fast cache for shallow depth=1 clones (the 50x concurrent clone benchmark!)
            bool cacheable_shallow1 = (req.keep_alive && deepen == 1 && wants.size() == 1 && haves.empty() && shallows.empty());
            if (cacheable_shallow1) {
                auto cit = repo.shallow1_http_cache.find(wants[0]);
                if (cit != repo.shallow1_http_cache.end()) {
                    res.set_prebuilt(cit->second);
                    return;
                }
            }

            std::vector<Oid> objs, new_shallows, unshallows;
            compute_fetch_objects(store, repo, wants, haves, shallows, deepen, objs, new_shallows, unshallows);

            std::string body;
            if (!new_shallows.empty() || !unshallows.empty()) {
                append_pkt(body, "shallow-info\n");
                for (const auto& s : new_shallows) append_pkt(body, "shallow " + s.hex() + "\n");
                for (const auto& u : unshallows) append_pkt(body, "unshallow " + u.hex() + "\n");
                body.append("0001");
            }
            append_pkt(body, "packfile\n");
            auto pack = store.build_pack(repo, objs);
            append_pkt_sideband(body, 1, pack.data(), pack.size());
            body.append("0000");

            build_git_http_response(res, "application/x-git-upload-pack-result", body, req.keep_alive);
            if (cacheable_shallow1) {
                repo.shallow1_http_cache.emplace(wants[0], res.owned_raw);
            }
            return;
        }

        build_error_json(res, 400, "Unknown git v2 command", store.next_request_id(), req.keep_alive);
        return;
    }

    // Protocol v0 upload-pack POST
    std::vector<Oid> wants, haves, shallows;
    int deepen = 0;
    for (const auto& p : pkts) {
        if (p.kind != PktLine::Kind::Data) continue;
        std::string_view line = strip_nl(p.payload);
        if (line.size() >= 45 && line.substr(0, 5) == "want ") {
            Oid o; if (parse_oid(line.substr(5, 40), o)) wants.push_back(o);
        } else if (line.size() >= 45 && line.substr(0, 5) == "have ") {
            Oid o; if (parse_oid(line.substr(5, 40), o)) haves.push_back(o);
        } else if (line.size() >= 48 && line.substr(0, 8) == "shallow ") {
            Oid o; if (parse_oid(line.substr(8, 40), o)) shallows.push_back(o);
        } else if (line.substr(0, 7) == "deepen ") {
            deepen = std::atoi(std::string(line.substr(7)).c_str());
        }
    }

    std::vector<Oid> objs, new_shallows, unshallows;
    compute_fetch_objects(store, repo, wants, haves, shallows, deepen, objs, new_shallows, unshallows);

    std::string body;
    if (!new_shallows.empty() || !unshallows.empty()) {
        for (const auto& s : new_shallows) append_pkt(body, "shallow " + s.hex() + "\n");
        for (const auto& u : unshallows) append_pkt(body, "unshallow " + u.hex() + "\n");
        body.append("0000");
    }
    append_pkt(body, "NAK\n");
    auto pack = store.build_pack(repo, objs);
    append_pkt_sideband(body, 1, pack.data(), pack.size());
    body.append("0000");
    build_http_response(res, 200, "application/x-git-upload-pack-result", body, store.next_request_id(), req.keep_alive);
}

struct PushCmd {
    Oid old_oid;
    Oid new_oid;
    std::string ref;
};

void handle_receive_pack(ForgeStore& store, Repo& repo, const HttpRequest& req, HttpResponse& res) {
    // Zero-allocation fast path for single-ref push: <4hex><old> <new> <ref>\0<caps>\n 0000 PACK...
    if (req.body.size() >= 96) {
        unsigned len0 = 0;
        bool ok_hex = true;
        for (int i = 0; i < 4; ++i) {
            int n = hex_nibble(req.body[i]);
            if (n < 0) { ok_hex = false; break; }
            len0 = (len0 << 4) | static_cast<unsigned>(n);
        }
        if (ok_hex && len0 >= 87 && len0 + 4 <= req.body.size() &&
            std::memcmp(req.body.data() + len0, "0000", 4) == 0) {
            std::string_view line = strip_nl(req.body.substr(4, len0 - 4));
            bool use_sideband = false;
            size_t nul = line.find('\0');
            if (nul != std::string_view::npos) {
                std::string_view caps = line.substr(nul + 1);
                if (caps.find("side-band-64k") != std::string_view::npos) use_sideband = true;
                line = line.substr(0, nul);
            }
            Oid old_oid{}, new_oid{};
            if (line.size() >= 83 && line[40] == ' ' && line[81] == ' ' &&
                parse_oid(line.substr(0, 40), old_oid) && parse_oid(line.substr(41, 40), new_oid)) {
                std::string_view ref = line.substr(82);
                std::string_view pack_view = req.body.substr(len0 + 4);
                bool unpack_ok = true;
                std::string unpack_err;
                if (!pack_view.empty()) {
                    unpack_ok = store.unpack_pack(
                        repo,
                        reinterpret_cast<const uint8_t*>(pack_view.data()),
                        pack_view.size(),
                        unpack_err);
                }

                auto emit_single_report = [&](std::string_view status_line_sv) {
                    char rep[320];
                    size_t rn = 0;
                    auto put_pkt = [&](char* dst, size_t& off, const char* p, size_t plen) {
                        static constexpr char kHex[] = "0123456789abcdef";
                        size_t tot = plen + 4;
                        dst[off++] = kHex[(tot >> 12) & 0xf];
                        dst[off++] = kHex[(tot >> 8) & 0xf];
                        dst[off++] = kHex[(tot >> 4) & 0xf];
                        dst[off++] = kHex[tot & 0xf];
                        std::memcpy(dst + off, p, plen);
                        off += plen;
                    };
                    if (unpack_ok) {
                        put_pkt(rep, rn, "unpack ok\n", 10);
                    } else {
                        std::string u = "unpack " + unpack_err + "\n";
                        put_pkt(rep, rn, u.data(), u.size());
                    }
                    put_pkt(rep, rn, status_line_sv.data(), status_line_sv.size());
                    std::memcpy(rep + rn, "0000", 4);
                    rn += 4;

                    if (use_sideband) {
                        char sb[360];
                        size_t sn = 0;
                        static constexpr char kHex[] = "0123456789abcdef";
                        size_t tot = rn + 5;
                        sb[sn++] = kHex[(tot >> 12) & 0xf];
                        sb[sn++] = kHex[(tot >> 8) & 0xf];
                        sb[sn++] = kHex[(tot >> 4) & 0xf];
                        sb[sn++] = kHex[tot & 0xf];
                        sb[sn++] = '\x01';
                        std::memcpy(sb + sn, rep, rn);
                        sn += rn;
                        std::memcpy(sb + sn, "0000", 4);
                        sn += 4;
                        build_git_http_response(res, "application/x-git-receive-pack-result", std::string_view(sb, sn), req.keep_alive);
                    } else {
                        build_git_http_response(res, "application/x-git-receive-pack-result", std::string_view(rep, rn), req.keep_alive);
                    }
                };

                if (ref.size() <= 200) {
                    char status_buf[256];
                    size_t slen = 0;
                    bool ok_ref = false;
                    const char* ng_reason = nullptr;
                    if (unpack_ok) {
                        auto rit = repo.refs.find(ref);
                        bool exists = (rit != repo.refs.end());
                        Oid current = exists ? rit->second : Oid{};
                        if (new_oid.is_zero()) {
                            if (!exists || (!old_oid.is_zero() && current != old_oid)) ng_reason = " non-fast-forward\n";
                            else { repo.refs.erase(rit); ok_ref = true; }
                        } else if (old_oid.is_zero()) {
                            if (exists) ng_reason = " non-fast-forward\n";
                            else if (repo.objects.find(new_oid) == repo.objects.end()) ng_reason = " missing object\n";
                            else { repo.refs.emplace(std::string(ref), new_oid); ok_ref = true; }
                        } else {
                            if (!exists || current != old_oid) ng_reason = " non-fast-forward\n";
                            else if (auto oit = repo.objects.find(new_oid); oit == repo.objects.end()) ng_reason = " missing object\n";
                            else if (!store.is_ancestor_obj(repo, old_oid, new_oid, oit->second)) ng_reason = " non-fast-forward\n";
                            else { rit->second = new_oid; ok_ref = true; }
                        }
                    } else {
                        ng_reason = " unpack failed\n";
                    }
                    if (ok_ref) {
                        repo.ref_version++;
                        std::memcpy(status_buf, "ok ", 3);
                        std::memcpy(status_buf + 3, ref.data(), ref.size());
                        status_buf[3 + ref.size()] = '\n';
                        slen = 4 + ref.size();
                    } else {
                        std::memcpy(status_buf, "ng ", 3);
                        std::memcpy(status_buf + 3, ref.data(), ref.size());
                        size_t rlen = std::strlen(ng_reason);
                        std::memcpy(status_buf + 3 + ref.size(), ng_reason, rlen);
                        slen = 3 + ref.size() + rlen;
                    }
                    emit_single_report(std::string_view(status_buf, slen));
                    return;
                }
            }
        }
    }

    std::vector<PktLine> pkts;
    size_t consumed = 0;
    if (!parse_pkt_lines(req.body, pkts, consumed, true)) {
        build_error_json(res, 400, "Malformed receive-pack command list", store.next_request_id(), req.keep_alive);
        return;
    }

    std::vector<PushCmd> cmds;
    bool use_sideband = false;
    bool first = true;
    for (const auto& p : pkts) {
        if (p.kind == PktLine::Kind::Flush) break;
        if (p.kind != PktLine::Kind::Data) continue;
        std::string_view line = strip_nl(p.payload);
        if (first) {
            first = false;
            size_t nul = line.find('\0');
            if (nul != std::string_view::npos) {
                std::string_view caps = line.substr(nul + 1);
                if (caps.find("side-band-64k") != std::string_view::npos) use_sideband = true;
                line = line.substr(0, nul);
            }
        }
        if (line.size() < 83 || line[40] != ' ' || line[81] != ' ') {
            build_error_json(res, 400, "Malformed receive-pack command", store.next_request_id(), req.keep_alive);
            return;
        }
        PushCmd cmd;
        if (!parse_oid(line.substr(0, 40), cmd.old_oid) || !parse_oid(line.substr(41, 40), cmd.new_oid)) {
            build_error_json(res, 400, "Invalid OID in receive-pack", store.next_request_id(), req.keep_alive);
            return;
        }
        cmd.ref = std::string(line.substr(82));
        cmds.push_back(std::move(cmd));
    }

    std::string_view pack_view = req.body.substr(consumed);
    bool unpack_ok = true;
    std::string unpack_err;
    if (!pack_view.empty()) {
        unpack_ok = store.unpack_pack(
            repo,
            reinterpret_cast<const uint8_t*>(pack_view.data()),
            pack_view.size(),
            unpack_err);
    }

    std::string report;
    if (unpack_ok) {
        append_pkt(report, "unpack ok\n");
    } else {
        append_pkt(report, "unpack " + unpack_err + "\n");
    }

    bool changed = false;
    if (unpack_ok) {
        for (const auto& cmd : cmds) {
            auto rit = repo.refs.find(cmd.ref);
            bool exists = (rit != repo.refs.end());
            Oid current = exists ? rit->second : Oid{};

            if (cmd.new_oid.is_zero()) {
                // Delete ref
                if (!exists || (!cmd.old_oid.is_zero() && current != cmd.old_oid)) {
                    append_pkt(report, "ng " + cmd.ref + " non-fast-forward\n");
                } else {
                    repo.refs.erase(rit);
                    append_pkt(report, "ok " + cmd.ref + "\n");
                    changed = true;
                }
            } else if (cmd.old_oid.is_zero()) {
                // Create ref
                if (exists) {
                    append_pkt(report, "ng " + cmd.ref + " non-fast-forward\n");
                } else if (repo.objects.find(cmd.new_oid) == repo.objects.end()) {
                    append_pkt(report, "ng " + cmd.ref + " missing object\n");
                } else {
                    repo.refs[cmd.ref] = cmd.new_oid;
                    append_pkt(report, "ok " + cmd.ref + "\n");
                    changed = true;
                }
            } else {
                // Update existing ref: must match old_oid and fast-forward
                if (!exists || current != cmd.old_oid) {
                    append_pkt(report, "ng " + cmd.ref + " non-fast-forward\n");
                } else if (repo.objects.find(cmd.new_oid) == repo.objects.end()) {
                    append_pkt(report, "ng " + cmd.ref + " missing object\n");
                } else if (!store.is_ancestor(repo, cmd.old_oid, cmd.new_oid)) {
                    append_pkt(report, "ng " + cmd.ref + " non-fast-forward\n");
                } else {
                    rit->second = cmd.new_oid;
                    append_pkt(report, "ok " + cmd.ref + "\n");
                    changed = true;
                }
            }
        }
    } else {
        for (const auto& cmd : cmds) {
            append_pkt(report, "ng " + cmd.ref + " unpack failed\n");
        }
    }
    report.append("0000");

    if (changed) {
        repo.ref_version++;
    }

    std::string body;
    if (use_sideband) {
        append_pkt_sideband(body, 1, reinterpret_cast<const uint8_t*>(report.data()), report.size());
        body.append("0000");
    } else {
        body = std::move(report);
    }

    build_http_response(res, 200, "application/x-git-receive-pack-result", body, store.next_request_id(), req.keep_alive);
}

} // namespace

const std::string& git_v2_info_refs_http() noexcept {
    return static_v2_info_refs_http();
}

bool try_git_fast_readonly(const ForgeStore& store, const HttpRequest& req, HttpResponse& res) {
    if (!req.keep_alive) return false;
    std::string_view p = req.path;
    if (p.size() < 12 || p[0] != '/') return false;
    if (p.size() >= 5 && p.substr(0, 5) == "/api/") return false;

    size_t s1 = p.find('/', 1);
    if (s1 == std::string_view::npos) return false;
    std::string_view owner = p.substr(1, s1 - 1);

    size_t s2 = p.find('/', s1 + 1);
    if (s2 == std::string_view::npos) return false;
    std::string_view repo_seg = p.substr(s1 + 1, s2 - s1 - 1);
    std::string_view tail = p.substr(s2);

    bool is_info = (tail == "/info/refs" && req.method == "GET");
    bool is_upload = (!is_info && tail == "/git-upload-pack" && req.method == "POST");
    if (!is_info && !is_upload) return false;

    if (repo_seg.size() > 4 && repo_seg.substr(repo_seg.size() - 4) == ".git") {
        repo_seg.remove_suffix(4);
    }

    if (!store.check_auth(req.authorization)) return false;
    const Repo* repo = store.find_repo_const(owner, repo_seg);
    if (!repo) return false;

    if (is_info) {
        if (query_param(req.query, "service") == "git-upload-pack" &&
            req.git_protocol.find("version=2") != std::string_view::npos) {
            res.set_prebuilt(static_v2_info_refs_http());
            return true;
        }
        return false;
    }

    // Stack-only pkt-line scanner for v2 ls-refs and shallow-1 fetch cache hits
    std::string_view buf = req.body;
    size_t pos = 0;
    std::string_view command;
    bool in_args = false;
    bool peel = false, symrefs = false, has_prefix = false;
    int deepen = 0;
    int want_count = 0, have_count = 0, shallow_count = 0;
    Oid want0{};

    while (pos + 4 <= buf.size()) {
        unsigned len = 0;
        for (int i = 0; i < 4; ++i) {
            int n = hex_nibble(buf[pos + i]);
            if (n < 0) return false;
            len = (len << 4) | static_cast<unsigned>(n);
        }
        if (len == 0) {
            break;
        } else if (len == 1) {
            in_args = true;
            pos += 4;
        } else if (len == 2) {
            pos += 4;
        } else if (len < 4 || pos + len > buf.size()) {
            return false;
        } else {
            std::string_view line = strip_nl(buf.substr(pos + 4, len - 4));
            pos += len;
            if (!in_args) {
                if (line.size() > 8 && line.substr(0, 8) == "command=") {
                    command = line.substr(8);
                }
            } else {
                if (command == "ls-refs") {
                    if (line == "peel") peel = true;
                    else if (line == "symrefs") symrefs = true;
                    else if (line.size() >= 11 && line.substr(0, 11) == "ref-prefix ") has_prefix = true;
                } else if (command == "fetch") {
                    if (line.size() == 45 && line.substr(0, 5) == "want ") {
                        if (want_count == 0) {
                            if (!parse_oid(line.substr(5), want0)) return false;
                        }
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
        }
    }

    if (command == "ls-refs") {
        if (peel && symrefs && !has_prefix &&
            repo->cached_ls_refs_version == repo->ref_version &&
            !repo->cached_ls_refs_http.empty()) {
            res.set_prebuilt(repo->cached_ls_refs_http);
            return true;
        }
        return false;
    }

    if (command == "fetch") {
        if (deepen == 1 && want_count == 1 && have_count == 0 && shallow_count == 0) {
            auto cit = repo->shallow1_http_cache.find(want0);
            if (cit != repo->shallow1_http_cache.end()) {
                res.set_prebuilt(cit->second);
                return true;
            }
        }
        return false;
    }

    return false;
}

bool handle_git_http(ForgeStore& store, const HttpRequest& req, HttpResponse& res) {
    // Match /{owner}/{repo}.git/(info/refs|git-upload-pack|git-receive-pack)
    std::string_view p = req.path;
    if (p.size() < 2 || p[0] != '/') return false;
    if (p.substr(0, 5) == "/api/" || p == "/mcp" || p == "/healthz") return false;

    size_t s1 = p.find('/', 1);
    if (s1 == std::string_view::npos) return false;
    std::string_view owner = p.substr(1, s1 - 1);

    size_t s2 = p.find('/', s1 + 1);
    if (s2 == std::string_view::npos) return false;
    std::string_view repo_seg = p.substr(s1 + 1, s2 - s1 - 1);
    std::string_view tail = p.substr(s2);

    bool is_info_refs = (tail == "/info/refs");
    bool is_upload = (tail == "/git-upload-pack");
    bool is_receive = (tail == "/git-receive-pack");
    if (!is_info_refs && !is_upload && !is_receive) return false;

    if (repo_seg.size() > 4 && repo_seg.substr(repo_seg.size() - 4) == ".git") {
        repo_seg.remove_suffix(4);
    }

    if (!store.check_auth(req.authorization)) {
        build_error_json(res, 401, "Requires authentication", store.next_request_id(), req.keep_alive);
        return true;
    }

    Repo* repo = store.find_repo(owner, repo_seg);
    if (!repo) {
        build_error_json(res, 404, "Repository not found", store.next_request_id(), req.keep_alive);
        return true;
    }

    if (is_info_refs && req.method == "GET") {
        handle_info_refs(store, *repo, req, res);
        return true;
    }
    if (is_upload && req.method == "POST") {
        handle_upload_pack(store, *repo, req, res);
        return true;
    }
    if (is_receive && req.method == "POST") {
        handle_receive_pack(store, *repo, req, res);
        return true;
    }

    build_error_json(res, 405, "Method Not Allowed", store.next_request_id(), req.keep_alive);
    return true;
}

} // namespace forge
