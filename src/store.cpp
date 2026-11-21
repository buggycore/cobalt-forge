#include "store.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <queue>

namespace forge {

ForgeStore::ForgeStore(std::string viewer_login, std::string auth_token, int64_t base_epoch)
    : viewer_login_(std::move(viewer_login)),
      auth_token_(std::move(auth_token)),
      base_epoch_(base_epoch) {
    if (!auth_token_.empty()) {
        expected_bearer_ = "Bearer " + auth_token_;
    }
    repos_.reserve(128);
    nodes_by_id_.reserve(4096);
    if (inflateInit(&inf_) == Z_OK) inf_ready_ = true;
    if (inflateInit2(&inf_raw_, -15) == Z_OK) inf_raw_ready_ = true;
    if (deflateInit(&def_, 9) == Z_OK) def_ready_ = true;
}

ForgeStore::~ForgeStore() {
    if (inf_ready_) inflateEnd(&inf_);
    if (inf_raw_ready_) inflateEnd(&inf_raw_);
    if (def_ready_) deflateEnd(&def_);
}

bool ForgeStore::check_auth(std::string_view auth_header) const noexcept {
    if (auth_token_.empty()) return true;
    if (auth_header.size() == expected_bearer_.size() &&
        std::memcmp(auth_header.data(), expected_bearer_.data(), expected_bearer_.size()) == 0) {
        return true;
    }
    if (auth_header.size() > 7 &&
        (auth_header[0] == 'b' || auth_header[0] == 'B') &&
        (auth_header[1] == 'e' || auth_header[1] == 'E') &&
        (auth_header[2] == 'a' || auth_header[2] == 'A') &&
        (auth_header[3] == 'r' || auth_header[3] == 'R') &&
        (auth_header[4] == 'e' || auth_header[4] == 'E') &&
        (auth_header[5] == 'r' || auth_header[5] == 'R') &&
        auth_header[6] == ' ') {
        return auth_header.substr(7) == auth_token_;
    }
    if (auth_header.size() > 6 && auth_header.substr(0, 6) == "token ") {
        return auth_header.substr(6) == auth_token_;
    }
    return false;
}

std::string ForgeStore::format_iso8601(int64_t epoch_sec) {
    std::time_t t = static_cast<std::time_t>(epoch_sec);
    std::tm tm_utc{};
    gmtime_r(&t, &tm_utc);
    char buf[32];
    int n = std::snprintf(
        buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
        tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
        tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec);
    return std::string(buf, static_cast<size_t>(n));
}

std::string ForgeStore::next_timestamp() {
    return format_iso8601(base_epoch_ + static_cast<int64_t>(++ts_counter_));
}

const char* ForgeStore::type_name(ObjType t) noexcept {
    switch (t) {
        case ObjType::Commit: return "commit";
        case ObjType::Tree: return "tree";
        case ObjType::Blob: return "blob";
        case ObjType::Tag: return "tag";
    }
    return "blob";
}

Oid ForgeStore::hash_object(ObjType type, const uint8_t* data, size_t len) noexcept {
    char hdr[32];
    const char* tn = type_name(type);
    size_t tlen = (type == ObjType::Commit) ? 6 : (type == ObjType::Tag ? 3 : 4);
    std::memcpy(hdr, tn, tlen);
    hdr[tlen] = ' ';
    char num[24];
    char* p = num + sizeof(num);
    size_t v = len;
    do {
        *--p = static_cast<char>('0' + (v % 10));
        v /= 10;
    } while (v != 0);
    size_t nlen = static_cast<size_t>((num + sizeof(num)) - p);
    std::memcpy(hdr + tlen + 1, p, nlen);
    hdr[tlen + 1 + nlen] = '\0';
    Sha1 sha;
    sha.update(hdr, tlen + nlen + 2);
    sha.update(data, len);
    return sha.final();
}

Repo* ForgeStore::create_repo(
    const std::string& name, bool is_private, const std::string& description, const std::string& default_branch) {
    if (repos_.find(name) != repos_.end()) return nullptr;
    auto repo = std::make_unique<Repo>();
    repo->db_id = next_db_id_++;
    repo->node_id = "R_" + std::to_string(repo->db_id);
    repo->owner = viewer_login_;
    repo->name = name;
    repo->description = description;
    repo->is_private = is_private;
    repo->default_branch = default_branch.empty() ? "main" : default_branch;
    repo->created_at = next_timestamp();
    Repo* ptr = repo.get();
    register_node(ptr->db_id, NodeLookup{NodeLookup::Kind::Repo, ptr, nullptr, nullptr});
    repo_order_.push_back(ptr);
    repos_.emplace(name, std::move(repo));
    last_repo_ = ptr;
    return ptr;
}

Repo* ForgeStore::find_repo(std::string_view owner, std::string_view name) noexcept {
    if (owner != viewer_login_) return nullptr;
    if (last_repo_ && last_repo_->name == name) return last_repo_;
    auto it = repos_.find(name);
    if (it == repos_.end()) return nullptr;
    last_repo_ = it->second.get();
    return last_repo_;
}

const Repo* ForgeStore::find_repo_const(std::string_view owner, std::string_view name) const noexcept {
    if (owner != viewer_login_) return nullptr;
    if (last_repo_ && last_repo_->name == name) return last_repo_;
    auto it = repos_.find(name);
    if (it == repos_.end()) return nullptr;
    return it->second.get();
}

bool ForgeStore::delete_repo(std::string_view owner, std::string_view name) {
    if (owner != viewer_login_) return false;
    auto it = repos_.find(name);
    if (it == repos_.end()) return false;
    Repo* ptr = it->second.get();
    if (last_repo_ == ptr) last_repo_ = nullptr;
    if (ptr->db_id < nodes_by_id_.size()) nodes_by_id_[ptr->db_id] = NodeLookup{};
    for (const auto& iss : ptr->issues) {
        if (iss.db_id < nodes_by_id_.size()) nodes_by_id_[iss.db_id] = NodeLookup{};
    }
    for (const auto& pr : ptr->pulls) {
        if (pr->db_id < nodes_by_id_.size()) nodes_by_id_[pr->db_id] = NodeLookup{};
    }
    repo_order_.erase(std::remove(repo_order_.begin(), repo_order_.end(), ptr), repo_order_.end());
    repos_.erase(it);
    return true;
}

static bool parse_uint64_sv(std::string_view sv, uint64_t& out) noexcept {
    if (sv.empty() || sv.size() > 19) return false;
    uint64_t v = 0;
    for (char c : sv) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<uint64_t>(c - '0');
    }
    out = v;
    return true;
}

bool ForgeStore::find_node(std::string_view node_id, NodeLookup& out) const noexcept {
    uint64_t id = 0;
    NodeLookup::Kind want = NodeLookup::Kind::None;
    if (node_id.size() > 2 && node_id[0] == 'R' && node_id[1] == '_') {
        if (!parse_uint64_sv(node_id.substr(2), id)) return false;
        want = NodeLookup::Kind::Repo;
    } else if (node_id.size() > 2 && node_id[0] == 'I' && node_id[1] == '_') {
        if (!parse_uint64_sv(node_id.substr(2), id)) return false;
        want = NodeLookup::Kind::Issue;
    } else if (node_id.size() > 3 && node_id[0] == 'P' && node_id[1] == 'R' && node_id[2] == '_') {
        if (!parse_uint64_sv(node_id.substr(3), id)) return false;
        want = NodeLookup::Kind::PullRequest;
    } else {
        return false;
    }
    if (id >= nodes_by_id_.size() || nodes_by_id_[id].kind != want) return false;
    out = nodes_by_id_[id];
    return true;
}

Label* ForgeStore::create_label(
    Repo& repo, const std::string& name, const std::string& color, const std::string& desc) {
    auto& lbl = repo.labels[name];
    if (lbl.id == 0) lbl.id = next_db_id_++;
    lbl.name = name;
    lbl.color = color.empty() ? "ededed" : color;
    lbl.description = desc;
    return &lbl;
}

Issue* ForgeStore::create_issue(
    Repo& repo, std::string title, std::string body, const std::vector<std::string>& labels, std::string& err) {
    for (const auto& lbl : labels) {
        if (repo.labels.find(lbl) == repo.labels.end()) {
            err = "Validation Failed: unknown label '" + lbl + "'";
            return nullptr;
        }
    }
    Issue& iss = repo.issues.emplace_back();
    iss.db_id = next_db_id_++;
    iss.number = repo.next_issue_number++;
    iss.created_seq = next_seq_++;
    iss.created_epoch = base_epoch_ + static_cast<int64_t>(++ts_counter_);
    iss.updated_epoch = iss.created_epoch;
    iss.title = std::move(title);
    iss.body = std::move(body);
    iss.closed = false;
    iss.labels = labels;
    register_node(iss.db_id, NodeLookup{NodeLookup::Kind::Issue, &repo, &iss, nullptr});
    return &iss;
}

Issue* ForgeStore::create_issue_fast(Repo& repo, std::string_view title, std::string_view body) {
    Issue& iss = repo.issues.emplace_back();
    iss.db_id = next_db_id_++;
    iss.number = repo.next_issue_number++;
    iss.created_seq = next_seq_++;
    iss.created_epoch = base_epoch_ + static_cast<int64_t>(++ts_counter_);
    iss.updated_epoch = iss.created_epoch;
    iss.title.assign(title.data(), title.size());
    iss.body.assign(body.data(), body.size());
    iss.closed = false;
    register_node(iss.db_id, NodeLookup{NodeLookup::Kind::Issue, &repo, &iss, nullptr});
    return &iss;
}

Comment* ForgeStore::add_comment(Repo& repo, Issue& issue, std::string body) {
    Comment c;
    c.id = next_db_id_++;
    c.node_id = "IC_" + std::to_string(c.id);
    c.body = std::move(body);
    c.author_login = viewer_login_;
    c.created_epoch = base_epoch_ + static_cast<int64_t>(++ts_counter_);
    issue.comments.push_back(std::move(c));
    issue.cached_http_response.clear();
    (void)repo;
    return &issue.comments.back();
}

void ForgeStore::parse_obj_meta(const Repo& repo, GitObj& obj) {
    if (obj.meta_parsed) return;
    obj.meta_parsed = true;
    if (obj.type == ObjType::Commit) {
        std::string_view sv = repo.raw_sv(obj);
        size_t pos = 0;
        while (pos < sv.size()) {
            size_t nl = sv.find('\n', pos);
            if (nl == std::string_view::npos) nl = sv.size();
            std::string_view line = sv.substr(pos, nl - pos);
            pos = (nl < sv.size()) ? nl + 1 : sv.size();
            if (line.empty()) break;
            if (line.size() == 45 && line.substr(0, 5) == "tree ") {
                parse_oid(line.substr(5), obj.tree_oid);
            } else if (line.size() == 47 && line.substr(0, 7) == "parent ") {
                Oid p;
                if (parse_oid(line.substr(7), p)) {
                    if (obj.parent_count == 0) {
                        obj.parent0 = p;
                        obj.parent_count = 1;
                    } else {
                        obj.extra_parents.push_back(p);
                        if (obj.parent_count < 255) ++obj.parent_count;
                    }
                }
            } else if (line[0] == 'a' || line[0] == 'c') {
                // In git commits, tree and parent headers always precede author/committer
                break;
            }
        }
    } else if (obj.type == ObjType::Tag) {
        std::string_view sv = repo.raw_sv(obj);
        size_t pos = 0;
        while (pos < sv.size()) {
            size_t nl = sv.find('\n', pos);
            if (nl == std::string_view::npos) nl = sv.size();
            std::string_view line = sv.substr(pos, nl - pos);
            pos = (nl < sv.size()) ? nl + 1 : sv.size();
            if (line.empty()) break;
            if (line.size() == 47 && line.substr(0, 7) == "object ") {
                parse_oid(line.substr(7), obj.tag_target);
            } else if (line.substr(0, 5) == "type ") {
                std::string_view tn = line.substr(5);
                if (tn == "commit") obj.tag_target_type = ObjType::Commit;
                else if (tn == "tree") obj.tag_target_type = ObjType::Tree;
                else if (tn == "blob") obj.tag_target_type = ObjType::Blob;
                else if (tn == "tag") obj.tag_target_type = ObjType::Tag;
            }
        }
    }
}

std::string_view ForgeStore::commit_message(const Repo& repo, const GitObj& obj) noexcept {
    std::string_view sv = repo.raw_sv(obj);
    size_t blank = sv.find("\n\n");
    if (blank == std::string_view::npos) return {};
    return sv.substr(blank + 2);
}

Oid ForgeStore::put_object_arena(Repo& repo, ObjType type, size_t raw_off, size_t raw_len) {
    const uint8_t* ptr = raw_len ? (repo.raw_arena.data() + raw_off) : nullptr;
    Oid oid = hash_object(type, ptr, raw_len);
    if (repo.objects.find(oid) != repo.objects.end()) {
        // Rollback duplicate bytes immediately (caller just appended [raw_off, raw_off + raw_len))
        repo.raw_arena.resize(raw_off);
        return oid;
    }
    GitObj obj;
    obj.type = type;
    obj.raw_off = static_cast<uint32_t>(raw_off);
    obj.raw_len = static_cast<uint32_t>(raw_len);
    repo.objects.emplace(oid, std::move(obj));
    return oid;
}

Oid ForgeStore::put_object_bytes(Repo& repo, ObjType type, const uint8_t* data, size_t len) {
    Oid oid = hash_object(type, data, len);
    if (repo.objects.find(oid) != repo.objects.end()) {
        return oid;
    }
    if (repo.raw_arena.empty() && repo.raw_arena.capacity() < (1u << 20)) {
        repo.raw_arena.reserve(1u << 20);
    }
    if (repo.objects.bucket_count() == 0) {
        repo.objects.reserve(4096);
    }
    size_t off = repo.raw_arena.size();
    if (len > 0) {
        repo.raw_arena.resize(off + len);
        std::memcpy(repo.raw_arena.data() + off, data, len);
    }
    GitObj obj;
    obj.type = type;
    obj.raw_off = static_cast<uint32_t>(off);
    obj.raw_len = static_cast<uint32_t>(len);
    repo.objects.emplace(oid, std::move(obj));
    return oid;
}

Oid ForgeStore::put_object(Repo& repo, ObjType type, const std::vector<uint8_t>& raw) {
    return put_object_bytes(repo, type, raw.data(), raw.size());
}

bool ForgeStore::inflate_into(
    const uint8_t* src, size_t max_len, size_t expected_size, uint8_t* dst, size_t& consumed) {
    // Fast raw-deflate path: inflates directly into dst (zero scratch copy, skips redundant Adler-32).
    if (inf_raw_ready_ && max_len >= 6 && (src[0] & 0x0fu) == 8 && (src[1] & 0x20u) == 0 &&
        (((static_cast<unsigned>(src[0]) << 8) | src[1]) % 31u) == 0u) {
        inflateReset(&inf_raw_);
        uint8_t dummy = 0;
        inf_raw_.next_in = const_cast<Bytef*>(src + 2);
        inf_raw_.avail_in = static_cast<uInt>(max_len - 2);
        inf_raw_.next_out = expected_size ? dst : &dummy;
        inf_raw_.avail_out = static_cast<uInt>(expected_size);
        int ret = inflate(&inf_raw_, Z_FINISH);
        if (ret == Z_STREAM_END && inf_raw_.avail_out == 0) {
            size_t raw_used = (max_len - 2) - inf_raw_.avail_in;
            if (2 + raw_used + 4 <= max_len) {
                consumed = 2 + raw_used + 4;
                return true;
            }
        }
    }

    if (!inf_ready_) return false;
    inflateReset(&inf_);
    uint8_t dummy = 0;
    inf_.next_in = const_cast<Bytef*>(src);
    inf_.avail_in = static_cast<uInt>(max_len);
    inf_.next_out = expected_size ? dst : &dummy;
    inf_.avail_out = static_cast<uInt>(expected_size);
    int ret = inflate(&inf_, Z_FINISH);
    if (ret == Z_STREAM_END && inf_.avail_out == 0) {
        consumed = max_len - inf_.avail_in;
        return true;
    }
    while (ret == Z_OK || ret == Z_BUF_ERROR) {
        if (inf_.avail_out == 0) {
            uint8_t extra[64];
            inf_.next_out = extra;
            inf_.avail_out = sizeof(extra);
            ret = inflate(&inf_, Z_FINISH);
            if (ret == Z_STREAM_END && inf_.avail_out == sizeof(extra)) {
                consumed = max_len - inf_.avail_in;
                return true;
            }
            return false;
        }
        ret = inflate(&inf_, Z_FINISH);
    }
    if (ret == Z_STREAM_END && inf_.avail_out == 0) {
        consumed = max_len - inf_.avail_in;
        return true;
    }
    return false;
}

bool ForgeStore::deflate_bytes(const uint8_t* src, size_t len, std::vector<uint8_t>& out) {
    if (!def_ready_) return false;
    deflateReset(&def_);
    uLong bound = deflateBound(&def_, static_cast<uLong>(len));
    out.resize(bound);
    def_.next_in = const_cast<Bytef*>(src);
    def_.avail_in = static_cast<uInt>(len);
    def_.next_out = out.data();
    def_.avail_out = static_cast<uInt>(bound);
    int ret = deflate(&def_, Z_FINISH);
    if (ret != Z_STREAM_END) return false;
    out.resize(bound - def_.avail_out);
    return true;
}

const std::vector<uint8_t>& ForgeStore::ensure_compressed(const Repo& repo, GitObj& obj) {
    if (obj.compressed.empty()) {
        deflate_bytes(repo.raw_data(obj), obj.raw_len, obj.compressed);
    }
    return obj.compressed;
}

bool ForgeStore::apply_delta(
    const uint8_t* base_data, size_t base_len, const uint8_t* delta_data, size_t delta_len, std::vector<uint8_t>& out) {
    size_t pos = 0;
    auto read_size = [&](size_t& val) -> bool {
        val = 0;
        int shift = 0;
        for (;;) {
            if (pos >= delta_len || shift > 60) return false;
            uint8_t b = delta_data[pos++];
            val |= static_cast<size_t>(b & 0x7fu) << shift;
            if ((b & 0x80u) == 0) return true;
            shift += 7;
        }
    };
    size_t src_size = 0, dst_size = 0;
    if (!read_size(src_size) || !read_size(dst_size)) return false;
    if (src_size != base_len) return false;
    out.resize(dst_size);
    size_t written = 0;
    while (pos < delta_len) {
        uint8_t op = delta_data[pos++];
        if (op & 0x80u) {
            size_t cp_off = 0, cp_sz = 0;
            if (op & 0x01u) { if (pos >= delta_len) return false; cp_off |= delta_data[pos++]; }
            if (op & 0x02u) { if (pos >= delta_len) return false; cp_off |= static_cast<size_t>(delta_data[pos++]) << 8; }
            if (op & 0x04u) { if (pos >= delta_len) return false; cp_off |= static_cast<size_t>(delta_data[pos++]) << 16; }
            if (op & 0x08u) { if (pos >= delta_len) return false; cp_off |= static_cast<size_t>(delta_data[pos++]) << 24; }
            if (op & 0x10u) { if (pos >= delta_len) return false; cp_sz |= delta_data[pos++]; }
            if (op & 0x20u) { if (pos >= delta_len) return false; cp_sz |= static_cast<size_t>(delta_data[pos++]) << 8; }
            if (op & 0x40u) { if (pos >= delta_len) return false; cp_sz |= static_cast<size_t>(delta_data[pos++]) << 16; }
            if (cp_sz == 0) cp_sz = 0x10000;
            if (cp_off + cp_sz > base_len || written + cp_sz > dst_size) return false;
            std::memcpy(out.data() + written, base_data + cp_off, cp_sz);
            written += cp_sz;
        } else if (op != 0) {
            if (pos + op > delta_len || written + op > dst_size) return false;
            std::memcpy(out.data() + written, delta_data + pos, op);
            pos += op;
            written += op;
        } else {
            return false;
        }
    }
    return written == dst_size;
}

bool ForgeStore::unpack_pack(Repo& repo, const uint8_t* data, size_t len, std::string& err) {
    if (len < 32) {
        err = "pack too short";
        return false;
    }
    if (std::memcmp(data, "PACK", 4) != 0) {
        err = "bad pack signature";
        return false;
    }
    uint32_t ver = (static_cast<uint32_t>(data[4]) << 24) | (static_cast<uint32_t>(data[5]) << 16) |
                   (static_cast<uint32_t>(data[6]) << 8) | static_cast<uint32_t>(data[7]);
    if (ver != 2 && ver != 3) {
        err = "unsupported pack version";
        return false;
    }
    uint32_t count = (static_cast<uint32_t>(data[8]) << 24) | (static_cast<uint32_t>(data[9]) << 16) |
                     (static_cast<uint32_t>(data[10]) << 8) | static_cast<uint32_t>(data[11]);
    size_t body_end = len - 20;
    Oid computed = Sha1::digest(data, body_end);
    if (std::memcmp(computed.bytes.data(), data + body_end, 20) != 0) {
        err = "pack checksum mismatch";
        return false;
    }

    if (repo.raw_arena.capacity() < (1u << 20)) repo.raw_arena.reserve(1u << 20);
    if (repo.objects.bucket_count() == 0) repo.objects.reserve(4096);

    struct PendingDelta {
        size_t offset = 0;
        bool is_ofs = false;
        size_t base_offset = 0;
        Oid base_oid{};
        std::vector<uint8_t> delta;
    };

    struct SmallOff {
        size_t offset = 0;
        Oid oid{};
    };
    SmallOff small_offs[16];
    size_t small_count = 0;
    std::unordered_map<size_t, Oid> offset_to_oid;
    auto record_offset = [&](size_t off, const Oid& oid) {
        if (small_count < 16) {
            small_offs[small_count++] = SmallOff{off, oid};
        } else {
            if (offset_to_oid.empty()) {
                offset_to_oid.reserve(count);
                for (size_t i = 0; i < small_count; ++i) {
                    offset_to_oid.emplace(small_offs[i].offset, small_offs[i].oid);
                }
            }
            offset_to_oid[off] = oid;
        }
    };
    auto lookup_offset = [&](size_t off, Oid& out_oid) -> bool {
        if (offset_to_oid.empty()) {
            for (size_t i = 0; i < small_count; ++i) {
                if (small_offs[i].offset == off) {
                    out_oid = small_offs[i].oid;
                    return true;
                }
            }
            return false;
        }
        auto it = offset_to_oid.find(off);
        if (it == offset_to_oid.end()) return false;
        out_oid = it->second;
        return true;
    };
    std::vector<PendingDelta> pending_deltas;

    size_t pos = 12;
    for (uint32_t idx = 0; idx < count; ++idx) {
        if (pos >= body_end) {
            err = "truncated pack entry";
            return false;
        }
        size_t entry_offset = pos;
        uint8_t c = data[pos++];
        uint8_t type_code = (c >> 4) & 0x07u;
        size_t size = c & 0x0fu;
        int shift = 4;
        while (c & 0x80u) {
            if (pos >= body_end || shift > 60) {
                err = "bad pack size varint";
                return false;
            }
            c = data[pos++];
            size |= static_cast<size_t>(c & 0x7fu) << shift;
            shift += 7;
        }

        if (type_code >= 1 && type_code <= 4) {
            size_t off = repo.raw_arena.size();
            repo.raw_arena.resize(off + size);
            size_t consumed = 0;
            if (!inflate_into(data + pos, body_end - pos, size, size ? (repo.raw_arena.data() + off) : nullptr, consumed)) {
                repo.raw_arena.resize(off);
                err = "zlib inflate failed";
                return false;
            }
            pos += consumed;
            Oid oid = put_object_arena(repo, static_cast<ObjType>(type_code), off, size);
            record_offset(entry_offset, oid);
        } else if (type_code == 6) {
            if (pos >= body_end) { err = "truncated ofs-delta"; return false; }
            uint8_t b = data[pos++];
            size_t back = b & 0x7fu;
            while (b & 0x80u) {
                if (pos >= body_end) { err = "truncated ofs-delta"; return false; }
                b = data[pos++];
                back = ((back + 1) << 7) | (b & 0x7fu);
            }
            if (back == 0 || back > entry_offset) { err = "bad ofs-delta base"; return false; }
            std::vector<uint8_t> delta(size);
            size_t consumed = 0;
            if (!inflate_into(data + pos, body_end - pos, size, size ? delta.data() : nullptr, consumed)) {
                err = "zlib inflate failed on ofs-delta";
                return false;
            }
            pos += consumed;
            size_t base_off = entry_offset - back;
            Oid base_oid{};
            if (lookup_offset(base_off, base_oid)) {
                auto oit = repo.objects.find(base_oid);
                if (oit != repo.objects.end()) {
                    std::vector<uint8_t> resolved;
                    if (!apply_delta(repo.raw_data(oit->second), oit->second.raw_len, delta.data(), delta.size(), resolved)) {
                        err = "ofs-delta apply failed";
                        return false;
                    }
                    Oid oid = put_object(repo, oit->second.type, resolved);
                    record_offset(entry_offset, oid);
                    continue;
                }
            }
            pending_deltas.push_back(PendingDelta{entry_offset, true, base_off, {}, std::move(delta)});
        } else if (type_code == 7) {
            if (pos + 20 > body_end) { err = "truncated ref-delta"; return false; }
            Oid base_oid;
            std::memcpy(base_oid.bytes.data(), data + pos, 20);
            pos += 20;
            std::vector<uint8_t> delta(size);
            size_t consumed = 0;
            if (!inflate_into(data + pos, body_end - pos, size, size ? delta.data() : nullptr, consumed)) {
                err = "zlib inflate failed on ref-delta";
                return false;
            }
            pos += consumed;
            auto oit = repo.objects.find(base_oid);
            if (oit != repo.objects.end()) {
                std::vector<uint8_t> resolved;
                if (!apply_delta(repo.raw_data(oit->second), oit->second.raw_len, delta.data(), delta.size(), resolved)) {
                    err = "ref-delta apply failed";
                    return false;
                }
                Oid oid = put_object(repo, oit->second.type, resolved);
                record_offset(entry_offset, oid);
            } else {
                pending_deltas.push_back(PendingDelta{entry_offset, false, 0, base_oid, std::move(delta)});
            }
        } else {
            err = "unknown pack object type";
            return false;
        }
    }

    while (!pending_deltas.empty()) {
        size_t before = pending_deltas.size();
        std::vector<PendingDelta> remaining;
        for (auto& pd : pending_deltas) {
            Oid base_oid = pd.base_oid;
            if (pd.is_ofs) {
                if (!lookup_offset(pd.base_offset, base_oid)) { remaining.push_back(std::move(pd)); continue; }
            }
            auto oit = repo.objects.find(base_oid);
            if (oit == repo.objects.end()) { remaining.push_back(std::move(pd)); continue; }
            std::vector<uint8_t> resolved;
            if (!apply_delta(repo.raw_data(oit->second), oit->second.raw_len, pd.delta.data(), pd.delta.size(), resolved)) {
                err = "delta apply failed";
                return false;
            }
            Oid oid = put_object(repo, oit->second.type, resolved);
            record_offset(pd.offset, oid);
        }
        if (remaining.size() == before) {
            err = "unresolved delta base";
            return false;
        }
        pending_deltas = std::move(remaining);
    }

    return true;
}

std::vector<uint8_t> ForgeStore::build_pack(Repo& repo, const std::vector<Oid>& oids) {
    std::vector<uint8_t> out;
    out.reserve(64 + oids.size() * 256);
    out.push_back('P'); out.push_back('A'); out.push_back('C'); out.push_back('K');
    out.push_back(0); out.push_back(0); out.push_back(0); out.push_back(2);
    uint32_t cnt = static_cast<uint32_t>(oids.size());
    out.push_back(static_cast<uint8_t>((cnt >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((cnt >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((cnt >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(cnt & 0xff));

    for (const Oid& oid : oids) {
        auto it = repo.objects.find(oid);
        if (it == repo.objects.end()) continue;
        GitObj& obj = it->second;
        size_t sz = obj.raw_len;
        uint8_t first = static_cast<uint8_t>((static_cast<uint8_t>(obj.type) << 4) | (sz & 0x0fu));
        sz >>= 4;
        if (sz > 0) first |= 0x80u;
        out.push_back(first);
        while (sz > 0) {
            uint8_t b = static_cast<uint8_t>(sz & 0x7fu);
            sz >>= 7;
            if (sz > 0) b |= 0x80u;
            out.push_back(b);
        }
        const auto& comp = ensure_compressed(repo, obj);
        out.insert(out.end(), comp.begin(), comp.end());
    }

    Oid trailer = Sha1::digest(out.data(), out.size());
    out.insert(out.end(), trailer.bytes.begin(), trailer.bytes.end());
    return out;
}

std::vector<TreeEntry> ForgeStore::parse_tree(const uint8_t* raw, size_t len) {
    std::vector<TreeEntry> entries;
    size_t pos = 0;
    while (pos < len) {
        size_t sp = pos;
        while (sp < len && raw[sp] != ' ') ++sp;
        if (sp >= len) break;
        size_t nul = sp + 1;
        while (nul < len && raw[nul] != 0) ++nul;
        if (nul + 21 > len) break;
        TreeEntry e;
        e.mode.assign(reinterpret_cast<const char*>(raw + pos), sp - pos);
        e.name.assign(reinterpret_cast<const char*>(raw + sp + 1), nul - sp - 1);
        std::memcpy(e.oid.bytes.data(), raw + nul + 1, 20);
        entries.push_back(std::move(e));
        pos = nul + 21;
    }
    return entries;
}

std::vector<uint8_t> ForgeStore::build_tree(std::vector<TreeEntry> entries) {
    std::sort(entries.begin(), entries.end(), [](const TreeEntry& a, const TreeEntry& b) {
        std::string ka = (a.mode == "40000") ? (a.name + "/") : a.name;
        std::string kb = (b.mode == "40000") ? (b.name + "/") : b.name;
        return ka < kb;
    });
    std::vector<uint8_t> out;
    out.reserve(entries.size() * 48);
    for (const auto& e : entries) {
        out.insert(out.end(), e.mode.begin(), e.mode.end());
        out.push_back(' ');
        out.insert(out.end(), e.name.begin(), e.name.end());
        out.push_back(0);
        out.insert(out.end(), e.oid.bytes.begin(), e.oid.bytes.end());
    }
    return out;
}

std::vector<uint8_t> ForgeStore::build_commit_bytes(
    const Oid& tree, const std::vector<Oid>& parents, const std::string& message) {
    int64_t ts = next_commit_epoch();
    std::string s;
    s.reserve(256 + message.size());
    s += "tree ";
    s += tree.hex();
    s += '\n';
    for (const auto& p : parents) {
        s += "parent ";
        s += p.hex();
        s += '\n';
    }
    std::string ident = viewer_login_ + " <" + viewer_login_ + "@example.invalid> " + std::to_string(ts) + " +0000";
    s += "author " + ident + "\n";
    s += "committer " + ident + "\n\n";
    s += message;
    return std::vector<uint8_t>(s.begin(), s.end());
}

bool ForgeStore::is_ancestor_obj(Repo& repo, const Oid& ancestor, const Oid& descendant, GitObj& desc_obj) {
    if (ancestor == descendant) return true;
    if (desc_obj.type != ObjType::Commit) return false;
    parse_obj_meta(repo, desc_obj);
    if (desc_obj.parent_count > 0) {
        if (desc_obj.parent0 == ancestor) return true;
        for (const auto& p : desc_obj.extra_parents) {
            if (p == ancestor) return true;
        }
    }
    std::unordered_set<Oid, OidHash> seen;
    std::vector<Oid> stack;
    desc_obj.for_each_parent([&](const Oid& p) { stack.push_back(p); });
    seen.insert(descendant);
    while (!stack.empty()) {
        Oid cur = stack.back();
        stack.pop_back();
        if (cur == ancestor) return true;
        if (!seen.insert(cur).second) continue;
        auto it = repo.objects.find(cur);
        if (it == repo.objects.end() || it->second.type != ObjType::Commit) continue;
        parse_obj_meta(repo, it->second);
        bool hit = false;
        it->second.for_each_parent([&](const Oid& p) {
            if (p == ancestor) hit = true;
            else if (seen.find(p) == seen.end()) stack.push_back(p);
        });
        if (hit) return true;
    }
    return false;
}

bool ForgeStore::is_ancestor(Repo& repo, const Oid& ancestor, const Oid& descendant) {
    if (ancestor == descendant) return true;
    auto dit = repo.objects.find(descendant);
    if (dit == repo.objects.end()) return false;
    return is_ancestor_obj(repo, ancestor, descendant, dit->second);
}

Oid ForgeStore::find_merge_base(Repo& repo, const Oid& a, const Oid& b) {
    if (a == b) return a;
    std::unordered_set<Oid, OidHash> anc_a;
    {
        std::queue<Oid> q;
        q.push(a);
        anc_a.insert(a);
        while (!q.empty()) {
            Oid cur = q.front();
            q.pop();
            auto it = repo.objects.find(cur);
            if (it == repo.objects.end() || it->second.type != ObjType::Commit) continue;
            parse_obj_meta(repo, it->second);
            it->second.for_each_parent([&](const Oid& p) {
                if (anc_a.insert(p).second) q.push(p);
            });
        }
    }
    std::unordered_set<Oid, OidHash> seen_b;
    std::queue<Oid> q;
    q.push(b);
    seen_b.insert(b);
    while (!q.empty()) {
        Oid cur = q.front();
        q.pop();
        if (anc_a.find(cur) != anc_a.end()) return cur;
        auto it = repo.objects.find(cur);
        if (it == repo.objects.end() || it->second.type != ObjType::Commit) continue;
        parse_obj_meta(repo, it->second);
        it->second.for_each_parent([&](const Oid& p) {
            if (seen_b.insert(p).second) q.push(p);
        });
    }
    return Oid{};
}

bool ForgeStore::resolve_ref_oid(Repo& repo, std::string_view ref_spec, Oid& out) {
    if (ref_spec.empty()) {
        auto it = repo.refs.find("refs/heads/" + repo.default_branch);
        if (it == repo.refs.end()) return false;
        out = it->second;
        return true;
    }
    auto it = repo.refs.find(std::string(ref_spec));
    if (it != repo.refs.end()) { out = it->second; return true; }
    it = repo.refs.find("refs/heads/" + std::string(ref_spec));
    if (it != repo.refs.end()) { out = it->second; return true; }
    it = repo.refs.find("refs/tags/" + std::string(ref_spec));
    if (it != repo.refs.end()) { out = peel_oid(repo, it->second); return true; }
    Oid parsed;
    if (parse_oid(ref_spec, parsed) && repo.objects.find(parsed) != repo.objects.end()) {
        out = parsed;
        return true;
    }
    return false;
}

Oid ForgeStore::peel_oid(Repo& repo, const Oid& start) {
    Oid cur = start;
    for (int depth = 0; depth < 16; ++depth) {
        auto it = repo.objects.find(cur);
        if (it == repo.objects.end() || it->second.type != ObjType::Tag) break;
        parse_obj_meta(repo, it->second);
        if (it->second.tag_target.is_zero()) break;
        cur = it->second.tag_target;
    }
    return cur;
}

void ForgeStore::flatten_tree(
    Repo& repo, const Oid& tree_oid, const std::string& prefix, std::map<std::string, Oid>& out) {
    if (tree_oid.is_zero()) return;
    auto it = repo.objects.find(tree_oid);
    if (it == repo.objects.end() || it->second.type != ObjType::Tree) return;
    auto entries = parse_tree(repo.raw_data(it->second), it->second.raw_len);
    for (const auto& e : entries) {
        std::string full = prefix.empty() ? e.name : (prefix + "/" + e.name);
        if (e.mode == "40000") {
            flatten_tree(repo, e.oid, full, out);
        } else {
            out[full] = e.oid;
        }
    }
}

Oid ForgeStore::build_tree_from_map(Repo& repo, const std::map<std::string, Oid>& files) {
    struct DirNode {
        std::map<std::string, Oid> files;
        std::map<std::string, std::unique_ptr<DirNode>> dirs;
    };
    DirNode root;
    for (const auto& [path, oid] : files) {
        size_t pos = 0;
        DirNode* cur = &root;
        for (;;) {
            size_t slash = path.find('/', pos);
            if (slash == std::string::npos) {
                cur->files[path.substr(pos)] = oid;
                break;
            }
            std::string seg = path.substr(pos, slash - pos);
            auto& child = cur->dirs[seg];
            if (!child) child = std::make_unique<DirNode>();
            cur = child.get();
            pos = slash + 1;
        }
    }
    auto build = [&](auto&& self, const DirNode& node) -> Oid {
        std::vector<TreeEntry> entries;
        entries.reserve(node.files.size() + node.dirs.size());
        for (const auto& [name, oid] : node.files) {
            entries.push_back(TreeEntry{"100644", name, oid});
        }
        for (const auto& [name, child] : node.dirs) {
            if (child->files.empty() && child->dirs.empty()) continue;
            Oid child_oid = self(self, *child);
            entries.push_back(TreeEntry{"40000", name, child_oid});
        }
        return put_object(repo, ObjType::Tree, build_tree(std::move(entries)));
    };
    return build(build, root);
}

bool ForgeStore::lookup_path_in_tree(
    Repo& repo, const Oid& root_tree, std::string_view path, bool& is_dir, Oid& out_oid) {
    while (!path.empty() && path.front() == '/') path.remove_prefix(1);
    while (!path.empty() && path.back() == '/') path.remove_suffix(1);
    if (path.empty()) {
        is_dir = true;
        out_oid = root_tree;
        return true;
    }
    Oid cur = root_tree;
    size_t pos = 0;
    while (pos < path.size()) {
        size_t slash = path.find('/', pos);
        bool last = (slash == std::string_view::npos);
        std::string_view seg = last ? path.substr(pos) : path.substr(pos, slash - pos);
        auto it = repo.objects.find(cur);
        if (it == repo.objects.end() || it->second.type != ObjType::Tree) return false;
        auto entries = parse_tree(repo.raw_data(it->second), it->second.raw_len);
        bool found = false;
        for (const auto& e : entries) {
            if (e.name == seg) {
                found = true;
                if (last) {
                    is_dir = (e.mode == "40000");
                    out_oid = e.oid;
                    return true;
                }
                if (e.mode != "40000") return false;
                cur = e.oid;
                break;
            }
        }
        if (!found) return false;
        pos = slash + 1;
    }
    return false;
}

bool ForgeStore::put_file_content(
    Repo& repo,
    std::string_view path,
    const std::vector<uint8_t>& content,
    const std::string& message,
    std::string_view branch_opt,
    std::string_view expected_sha_hex,
    Oid& out_blob_oid,
    Oid& out_commit_oid,
    bool& out_created,
    int& out_status,
    std::string& out_err) {
    while (!path.empty() && path.front() == '/') path.remove_prefix(1);
    while (!path.empty() && path.back() == '/') path.remove_suffix(1);
    if (path.empty()) {
        out_status = 422;
        out_err = "Invalid path";
        return false;
    }
    std::string branch = branch_opt.empty() ? repo.default_branch : std::string(branch_opt);
    std::string ref_name = "refs/heads/" + branch;

    Oid parent_oid{};
    bool has_parent = false;
    auto rit = repo.refs.find(ref_name);
    if (rit != repo.refs.end()) {
        parent_oid = rit->second;
        has_parent = true;
    } else if (!branch_opt.empty()) {
        auto dit = repo.refs.find("refs/heads/" + repo.default_branch);
        if (dit != repo.refs.end()) {
            parent_oid = dit->second;
            has_parent = true;
        }
    }

    std::map<std::string, Oid> files;
    if (has_parent) {
        auto cit = repo.objects.find(parent_oid);
        if (cit != repo.objects.end() && cit->second.type == ObjType::Commit) {
            parse_obj_meta(repo, cit->second);
            flatten_tree(repo, cit->second.tree_oid, "", files);
        }
    }

    std::string pstr(path);
    auto fit = files.find(pstr);
    bool exists = (fit != files.end());
    if (exists) {
        if (expected_sha_hex.empty()) {
            out_status = 409;
            out_err = "Invalid request: sha wasn't supplied for update";
            return false;
        }
        Oid exp;
        if (!parse_oid(expected_sha_hex, exp) || exp != fit->second) {
            out_status = 409;
            out_err = "Content sha does not match current file sha";
            return false;
        }
        out_created = false;
    } else {
        out_created = true;
    }

    out_blob_oid = put_object(repo, ObjType::Blob, content);
    files[pstr] = out_blob_oid;
    Oid new_tree = build_tree_from_map(repo, files);
    std::vector<Oid> parents;
    if (has_parent) parents.push_back(parent_oid);
    auto commit_bytes = build_commit_bytes(new_tree, parents, message);
    out_commit_oid = put_object(repo, ObjType::Commit, std::move(commit_bytes));
    repo.refs[ref_name] = out_commit_oid;
    repo.ref_version++;
    out_status = out_created ? 201 : 200;
    return true;
}

bool ForgeStore::delete_file_content(
    Repo& repo,
    std::string_view path,
    const std::string& message,
    std::string_view branch_opt,
    std::string_view expected_sha_hex,
    Oid& out_commit_oid,
    int& out_status,
    std::string& out_err) {
    while (!path.empty() && path.front() == '/') path.remove_prefix(1);
    while (!path.empty() && path.back() == '/') path.remove_suffix(1);
    std::string branch = branch_opt.empty() ? repo.default_branch : std::string(branch_opt);
    std::string ref_name = "refs/heads/" + branch;

    auto rit = repo.refs.find(ref_name);
    if (rit == repo.refs.end()) {
        out_status = 404;
        out_err = "Not Found";
        return false;
    }
    Oid parent_oid = rit->second;
    std::map<std::string, Oid> files;
    auto cit = repo.objects.find(parent_oid);
    if (cit != repo.objects.end() && cit->second.type == ObjType::Commit) {
        parse_obj_meta(repo, cit->second);
        flatten_tree(repo, cit->second.tree_oid, "", files);
    }

    std::string pstr(path);
    auto fit = files.find(pstr);
    if (fit == files.end()) {
        out_status = 404;
        out_err = "Not Found";
        return false;
    }
    if (!expected_sha_hex.empty()) {
        Oid exp;
        if (!parse_oid(expected_sha_hex, exp) || exp != fit->second) {
            out_status = 409;
            out_err = "Content sha does not match current file sha";
            return false;
        }
    }
    files.erase(fit);
    Oid new_tree = build_tree_from_map(repo, files);
    auto commit_bytes = build_commit_bytes(new_tree, {parent_oid}, message);
    out_commit_oid = put_object(repo, ObjType::Commit, std::move(commit_bytes));
    repo.refs[ref_name] = out_commit_oid;
    repo.ref_version++;
    out_status = 200;
    return true;
}

static uint32_t count_lines(const uint8_t* data, size_t len) {
    if (len == 0) return 0;
    uint32_t n = 0;
    for (size_t i = 0; i < len; ++i) if (data[i] == '\n') ++n;
    if (data[len - 1] != '\n') ++n;
    return n;
}

PullRequest* ForgeStore::create_pull(
    Repo& repo, std::string title, std::string body, const std::string& head_in, const std::string& base_in, std::string& err) {
    std::string head = head_in;
    auto colon = head.find(':');
    if (colon != std::string::npos) head = head.substr(colon + 1);
    std::string base = base_in.empty() ? repo.default_branch : base_in;

    Oid head_oid{}, base_oid{};
    if (!resolve_ref_oid(repo, head, head_oid)) {
        err = "Head branch not found: " + head;
        return nullptr;
    }
    if (!resolve_ref_oid(repo, base, base_oid)) {
        err = "Base branch not found: " + base;
        return nullptr;
    }
    auto pr = std::make_unique<PullRequest>();
    pr->db_id = next_db_id_++;
    pr->node_id = "PR_" + std::to_string(pr->db_id);
    pr->number = repo.next_pull_number++;
    pr->created_seq = next_seq_++;
    pr->title = std::move(title);
    pr->body = std::move(body);
    pr->head_ref = head;
    pr->head_sha = head_oid;
    pr->base_ref = base;
    pr->base_sha = base_oid;
    pr->created_at = next_timestamp();
    pr->updated_at = pr->created_at;
    PullRequest* ptr = pr.get();
    repo.pull_by_number[ptr->number] = ptr;
    register_node(ptr->db_id, NodeLookup{NodeLookup::Kind::PullRequest, &repo, nullptr, ptr});
    repo.pulls.push_back(std::move(pr));
    return ptr;
}

std::vector<DiffFile> ForgeStore::diff_pull(Repo& repo, const PullRequest& pr) {
    Oid head_oid = pr.head_sha;
    Oid base_oid = pr.base_sha;
    if (!pr.merged) {
        resolve_ref_oid(repo, pr.head_ref, head_oid);
        resolve_ref_oid(repo, pr.base_ref, base_oid);
    }
    Oid mb = find_merge_base(repo, base_oid, head_oid);
    Oid cmp_base = mb.is_zero() ? base_oid : mb;

    std::map<std::string, Oid> base_files, head_files;
    if (auto it = repo.objects.find(cmp_base); it != repo.objects.end() && it->second.type == ObjType::Commit) {
        parse_obj_meta(repo, it->second);
        flatten_tree(repo, it->second.tree_oid, "", base_files);
    }
    if (auto it = repo.objects.find(head_oid); it != repo.objects.end() && it->second.type == ObjType::Commit) {
        parse_obj_meta(repo, it->second);
        flatten_tree(repo, it->second.tree_oid, "", head_files);
    }

    std::vector<DiffFile> diffs;
    for (const auto& [path, h_oid] : head_files) {
        auto bit = base_files.find(path);
        if (bit == base_files.end()) {
            uint32_t add = 1;
            if (auto oit = repo.objects.find(h_oid); oit != repo.objects.end()) {
                add = std::max<uint32_t>(1, count_lines(repo.raw_data(oit->second), oit->second.raw_len));
            }
            diffs.push_back(DiffFile{path, "added", add, 0, add, h_oid});
        } else if (bit->second != h_oid) {
            uint32_t bl = 1, hl = 1;
            if (auto oit = repo.objects.find(bit->second); oit != repo.objects.end()) bl = std::max<uint32_t>(1, count_lines(repo.raw_data(oit->second), oit->second.raw_len));
            if (auto oit = repo.objects.find(h_oid); oit != repo.objects.end()) hl = std::max<uint32_t>(1, count_lines(repo.raw_data(oit->second), oit->second.raw_len));
            diffs.push_back(DiffFile{path, "modified", hl, bl, hl + bl, h_oid});
        }
    }
    for (const auto& [path, b_oid] : base_files) {
        if (head_files.find(path) == head_files.end()) {
            uint32_t del = 1;
            if (auto oit = repo.objects.find(b_oid); oit != repo.objects.end()) {
                del = std::max<uint32_t>(1, count_lines(repo.raw_data(oit->second), oit->second.raw_len));
            }
            diffs.push_back(DiffFile{path, "removed", 0, del, del, b_oid});
        }
    }
    std::sort(diffs.begin(), diffs.end(), [](const DiffFile& a, const DiffFile& b) {
        return a.filename < b.filename;
    });
    return diffs;
}

bool ForgeStore::is_pull_mergeable(Repo& repo, const PullRequest& pr) {
    if (pr.merged || pr.closed) return false;
    Oid head_oid = pr.head_sha;
    Oid base_oid = pr.base_sha;
    resolve_ref_oid(repo, pr.head_ref, head_oid);
    resolve_ref_oid(repo, pr.base_ref, base_oid);
    Oid mb = find_merge_base(repo, base_oid, head_oid);

    std::map<std::string, Oid> m_files, b_files, h_files;
    if (!mb.is_zero()) {
        if (auto it = repo.objects.find(mb); it != repo.objects.end() && it->second.type == ObjType::Commit) {
            parse_obj_meta(repo, it->second);
            flatten_tree(repo, it->second.tree_oid, "", m_files);
        }
    }
    if (auto it = repo.objects.find(base_oid); it != repo.objects.end() && it->second.type == ObjType::Commit) {
        parse_obj_meta(repo, it->second);
        flatten_tree(repo, it->second.tree_oid, "", b_files);
    }
    if (auto it = repo.objects.find(head_oid); it != repo.objects.end() && it->second.type == ObjType::Commit) {
        parse_obj_meta(repo, it->second);
        flatten_tree(repo, it->second.tree_oid, "", h_files);
    }

    std::unordered_set<std::string> all_paths;
    for (const auto& kv : m_files) all_paths.insert(kv.first);
    for (const auto& kv : b_files) all_paths.insert(kv.first);
    for (const auto& kv : h_files) all_paths.insert(kv.first);

    auto get_or_zero = [](const std::map<std::string, Oid>& m, const std::string& k) -> Oid {
        auto it = m.find(k);
        return it == m.end() ? Oid{} : it->second;
    };
    for (const auto& p : all_paths) {
        Oid mo = get_or_zero(m_files, p);
        Oid bo = get_or_zero(b_files, p);
        Oid ho = get_or_zero(h_files, p);
        if (ho != mo && bo != mo && bo != ho) return false;
    }
    return true;
}

bool ForgeStore::merge_pull(
    Repo& repo, PullRequest& pr, const std::string& method, Oid& out_sha, std::string& err, int& http_status) {
    if (pr.merged || pr.closed) {
        http_status = 405;
        err = "Pull Request is not mergeable";
        return false;
    }
    Oid head_oid = pr.head_sha;
    Oid base_oid = pr.base_sha;
    resolve_ref_oid(repo, pr.head_ref, head_oid);
    resolve_ref_oid(repo, pr.base_ref, base_oid);
    Oid mb = find_merge_base(repo, base_oid, head_oid);

    std::map<std::string, Oid> m_files, b_files, h_files;
    if (!mb.is_zero()) {
        if (auto it = repo.objects.find(mb); it != repo.objects.end() && it->second.type == ObjType::Commit) {
            parse_obj_meta(repo, it->second);
            flatten_tree(repo, it->second.tree_oid, "", m_files);
        }
    }
    if (auto it = repo.objects.find(base_oid); it != repo.objects.end() && it->second.type == ObjType::Commit) {
        parse_obj_meta(repo, it->second);
        flatten_tree(repo, it->second.tree_oid, "", b_files);
    }
    if (auto it = repo.objects.find(head_oid); it != repo.objects.end() && it->second.type == ObjType::Commit) {
        parse_obj_meta(repo, it->second);
        flatten_tree(repo, it->second.tree_oid, "", h_files);
    }

    std::unordered_set<std::string> all_paths;
    for (const auto& kv : m_files) all_paths.insert(kv.first);
    for (const auto& kv : b_files) all_paths.insert(kv.first);
    for (const auto& kv : h_files) all_paths.insert(kv.first);

    auto get_or_zero = [](const std::map<std::string, Oid>& m, const std::string& k) -> Oid {
        auto it = m.find(k);
        return it == m.end() ? Oid{} : it->second;
    };

    std::map<std::string, Oid> merged_files;
    for (const auto& p : all_paths) {
        Oid mo = get_or_zero(m_files, p);
        Oid bo = get_or_zero(b_files, p);
        Oid ho = get_or_zero(h_files, p);
        Oid chosen;
        if (ho == mo) {
            chosen = bo;
        } else if (bo == mo) {
            chosen = ho;
        } else if (bo == ho) {
            chosen = bo;
        } else {
            http_status = 405;
            err = "Merge conflict on " + p;
            return false;
        }
        if (!chosen.is_zero()) merged_files[p] = chosen;
    }

    Oid merged_tree = build_tree_from_map(repo, merged_files);
    std::vector<Oid> parents;
    parents.push_back(base_oid);
    if (method == "merge" && head_oid != base_oid) {
        parents.push_back(head_oid);
    }
    std::string msg = pr.title + " (#" + std::to_string(pr.number) + ")";
    auto commit_bytes = build_commit_bytes(merged_tree, parents, msg);
    out_sha = put_object(repo, ObjType::Commit, std::move(commit_bytes));

    repo.refs["refs/heads/" + pr.base_ref] = out_sha;
    repo.ref_version++;

    pr.closed = true;
    pr.merged = true;
    pr.merged_at = next_timestamp();
    pr.updated_at = pr.merged_at;
    pr.merge_commit_sha = out_sha;
    pr.head_sha = head_oid;
    pr.base_sha = base_oid;
    http_status = 200;
    return true;
}

void ForgeStore::append_repo_json(const Repo& repo, std::string& out) {
    out += "{\"id\":";
    out += std::to_string(repo.db_id);
    out += ",\"name\":";
    append_json_escaped(out, repo.name);
    out += ",\"full_name\":";
    append_json_escaped(out, repo.owner + "/" + repo.name);
    out += ",\"private\":";
    out += repo.is_private ? "true" : "false";
    out += ",\"owner\":{\"login\":";
    append_json_escaped(out, repo.owner);
    out += "},\"description\":";
    append_json_escaped(out, repo.description);
    out += ",\"default_branch\":";
    append_json_escaped(out, repo.default_branch);
    out += "}";
}

// Compact Issue JSON containing all fields required by REST, GraphQL cross-checks, and MCP parity.
void ForgeStore::append_issue_json(const Repo& repo, const Issue& issue, std::string& out) {
    auto append_dec = [&](uint64_t v) {
        char tmp[24];
        char* p = tmp + sizeof(tmp);
        do {
            *--p = static_cast<char>('0' + (v % 10));
            v /= 10;
        } while (v != 0);
        out.append(p, static_cast<size_t>((tmp + sizeof(tmp)) - p));
    };
    out.append("{\"id\":", 6);
    append_dec(issue.db_id);
    out.append(",\"number\":", 10);
    append_dec(issue.number);
    out.append(",\"title\":", 9);
    append_json_escaped(out, issue.title);
    out.append(",\"body\":", 8);
    append_json_escaped(out, issue.body);
    out.append(",\"state\":", 9);
    if (issue.closed) out.append("\"closed\"", 8);
    else out.append("\"open\"", 6);
    out.append(",\"labels\":[", 11);
    for (size_t i = 0; i < issue.labels.size(); ++i) {
        if (i > 0) out.push_back(',');
        auto it = repo.labels.find(issue.labels[i]);
        out.append("{\"name\":", 8);
        append_json_escaped(out, issue.labels[i]);
        out.append(",\"color\":", 9);
        append_json_escaped(out, it != repo.labels.end() ? it->second.color : std::string("ededed"));
        out.push_back('}');
    }
    out.append("]}", 2);
}

void ForgeStore::append_pull_json(const Repo& repo, const PullRequest& pr, std::string& out) {
    out += "{\"id\":";
    out += std::to_string(pr.db_id);
    out += ",\"number\":";
    out += std::to_string(pr.number);
    out += ",\"state\":";
    out += pr.closed ? "\"closed\"" : "\"open\"";
    out += ",\"title\":";
    append_json_escaped(out, pr.title);
    out += ",\"body\":";
    append_json_escaped(out, pr.body);
    out += ",\"merged\":";
    out += pr.merged ? "true" : "false";
    out += ",\"merged_at\":";
    if (pr.merged && !pr.merged_at.empty()) append_json_escaped(out, pr.merged_at);
    else out += "null";
    out += ",\"merge_commit_sha\":";
    if (pr.merged && !pr.merge_commit_sha.is_zero()) append_json_escaped(out, pr.merge_commit_sha.hex());
    else out += "null";
    out += ",\"head\":{\"ref\":";
    append_json_escaped(out, pr.head_ref);
    out += ",\"sha\":";
    append_json_escaped(out, pr.head_sha.hex());
    out += "},\"base\":{\"ref\":";
    append_json_escaped(out, pr.base_ref);
    out += ",\"sha\":";
    append_json_escaped(out, pr.base_sha.hex());
    out += "}}";
    (void)repo;
}

const std::string& ForgeStore::get_or_build_issue_http(const Repo& repo, Issue& issue) {
    if (issue.cached_http_response.empty()) {
        std::string body;
        body.reserve(128 + issue.title.size() + issue.body.size());
        append_issue_json(repo, issue, body);

        std::string resp;
        resp.reserve(96 + body.size());
        resp += "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "X-GitHub-Request-Id: ";
        resp += std::to_string(++req_counter_);
        resp += "\r\nContent-Length: ";
        resp += std::to_string(body.size());
        resp += "\r\n\r\n";
        resp += body;
        issue.cached_http_response = std::move(resp);
    }
    return issue.cached_http_response;
}

} // namespace forge
