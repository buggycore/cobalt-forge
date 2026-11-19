#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <zlib.h>

#include "json.hpp"
#include "sha1.hpp"

namespace forge {

struct TransparentStringHash {
    using is_transparent = void;
    size_t operator()(std::string_view sv) const noexcept {
        return std::hash<std::string_view>{}(sv);
    }
    size_t operator()(const std::string& s) const noexcept {
        return std::hash<std::string_view>{}(s);
    }
};

enum class ObjType : uint8_t {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
};

struct TreeEntry {
    std::string mode;
    std::string name;
    Oid oid;
};

struct GitObj {
    ObjType type = ObjType::Blob;
    std::vector<uint8_t> raw;
    std::vector<uint8_t> compressed;
    Oid tree_oid{};
    std::vector<Oid> parents;
    Oid tag_target{};
    ObjType tag_target_type = ObjType::Commit;
    bool meta_parsed = false;
};

struct Label {
    uint64_t id = 0;
    std::string name;
    std::string color;
    std::string description;
};

struct Comment {
    uint64_t id = 0;
    std::string node_id;
    std::string body;
    std::string author_login;
    int64_t created_epoch = 0;
};

struct Issue {
    uint64_t db_id = 0;
    uint32_t number = 0;
    uint64_t created_seq = 0;
    int64_t created_epoch = 0;
    int64_t updated_epoch = 0;
    std::string title;
    std::string body;
    bool closed = false;
    std::vector<std::string> labels;
    std::vector<Comment> comments;

    // Pre-rendered HTTP/1.1 200 OK response for GET /api/v3/repos/{o}/{r}/issues/{n}
    std::string cached_http_response;
    size_t cached_req_id_offset = 0;

    std::string node_id() const { return "I_" + std::to_string(db_id); }
};

struct PullRequest {
    uint64_t db_id = 0;
    std::string node_id;
    uint32_t number = 0;
    uint64_t created_seq = 0;
    std::string title;
    std::string body;
    std::string head_ref;
    Oid head_sha{};
    std::string base_ref;
    Oid base_sha{};
    bool closed = false;
    bool merged = false;
    std::string merged_at;
    Oid merge_commit_sha{};
    std::string created_at;
    std::string updated_at;
};

struct DiffFile {
    std::string filename;
    std::string status; // "added", "modified", "removed"
    uint32_t additions = 0;
    uint32_t deletions = 0;
    uint32_t changes = 0;
    Oid sha{};
};

struct Repo {
    uint64_t db_id = 0;
    std::string node_id;
    std::string owner;
    std::string name;
    std::string description;
    bool is_private = false;
    std::string default_branch = "main";
    std::string created_at;

    std::unordered_map<Oid, GitObj, OidHash> objects;
    std::map<std::string, Oid> refs;

    std::unordered_map<std::string, Label> labels;
    std::vector<std::unique_ptr<Issue>> issues;
    std::vector<std::unique_ptr<PullRequest>> pulls;
    std::unordered_map<uint32_t, PullRequest*> pull_by_number;
    uint32_t next_issue_number = 1;
    uint32_t next_pull_number = 1;

    // O(1) direct array lookup for issues (numbers are 1..N contiguous!)
    Issue* find_issue(uint32_t number) noexcept {
        if (number >= 1 && number <= issues.size()) {
            Issue* ptr = issues[number - 1].get();
            if (ptr && ptr->number == number) return ptr;
        }
        for (const auto& up : issues) {
            if (up->number == number) return up.get();
        }
        return nullptr;
    }
    const Issue* find_issue_const(uint32_t number) const noexcept {
        if (number >= 1 && number <= issues.size()) {
            const Issue* ptr = issues[number - 1].get();
            if (ptr && ptr->number == number) return ptr;
        }
        for (const auto& up : issues) {
            if (up->number == number) return up.get();
        }
        return nullptr;
    }

    // Performance caches
    uint64_t ref_version = 1;
    uint64_t cached_ls_refs_version = 0;
    std::string cached_ls_refs_http;
    std::unordered_map<Oid, std::string, OidHash> shallow1_http_cache;
    uint64_t cached_recv_refs_version = 0;
    std::string cached_recv_refs_http;
};

struct NodeLookup {
    enum class Kind : uint8_t { Repo, Issue, PullRequest, Comment };
    Kind kind;
    Repo* repo = nullptr;
    Issue* issue = nullptr;
    PullRequest* pull = nullptr;
};

class ForgeStore {
public:
    ForgeStore(std::string viewer_login, std::string auth_token, int64_t base_epoch);
    ~ForgeStore();

    ForgeStore(const ForgeStore&) = delete;
    ForgeStore& operator=(const ForgeStore&) = delete;

    const std::string& viewer_login() const noexcept { return viewer_login_; }
    const std::string& auth_token() const noexcept { return auth_token_; }
    bool check_auth(std::string_view auth_header) const noexcept;
    uint64_t next_request_id() noexcept { return ++req_counter_; }

    static std::string format_iso8601(int64_t epoch_sec);
    std::string next_timestamp();
    int64_t next_commit_epoch() noexcept { return base_epoch_ + static_cast<int64_t>(++ts_counter_); }

    // Repositories
    Repo* create_repo(const std::string& name, bool is_private, const std::string& description, const std::string& default_branch = "main");
    Repo* find_repo(std::string_view owner, std::string_view name) noexcept;
    const Repo* find_repo_const(std::string_view owner, std::string_view name) const noexcept;
    bool delete_repo(std::string_view owner, std::string_view name);
    const std::vector<Repo*>& list_repos() const noexcept { return repo_order_; }

    // Node lookup (GraphQL Relay global IDs)
    bool find_node(std::string_view node_id, NodeLookup& out) const noexcept;

    // Issues, Labels, Comments
    Label* create_label(Repo& repo, const std::string& name, const std::string& color, const std::string& desc);
    Issue* create_issue(Repo& repo, std::string title, std::string body, const std::vector<std::string>& labels, std::string& err);
    Comment* add_comment(Repo& repo, Issue& issue, std::string body);

    // Pull Requests
    PullRequest* create_pull(Repo& repo, std::string title, std::string body, const std::string& head, const std::string& base, std::string& err);
    bool is_pull_mergeable(Repo& repo, const PullRequest& pr);
    bool merge_pull(Repo& repo, PullRequest& pr, const std::string& method, Oid& out_sha, std::string& err, int& http_status);
    std::vector<DiffFile> diff_pull(Repo& repo, const PullRequest& pr);

    // Git Objects & Packfiles
    static Oid hash_object(ObjType type, const uint8_t* data, size_t len) noexcept;
    static const char* type_name(ObjType t) noexcept;
    Oid put_object(Repo& repo, ObjType type, std::vector<uint8_t> raw, std::vector<uint8_t> compressed = {});
    const std::vector<uint8_t>& ensure_compressed(GitObj& obj);
    void parse_obj_meta(GitObj& obj);
    static std::string_view commit_message(const GitObj& obj) noexcept;

    bool unpack_pack(Repo& repo, const uint8_t* data, size_t len, std::string& err);
    std::vector<uint8_t> build_pack(Repo& repo, const std::vector<Oid>& oids);

    // Git Tree / Commit / Graph helpers
    static std::vector<TreeEntry> parse_tree(const std::vector<uint8_t>& raw);
    static std::vector<uint8_t> build_tree(std::vector<TreeEntry> entries);
    std::vector<uint8_t> build_commit_bytes(const Oid& tree, const std::vector<Oid>& parents, const std::string& message);

    bool is_ancestor(Repo& repo, const Oid& ancestor, const Oid& descendant);
    Oid find_merge_base(Repo& repo, const Oid& a, const Oid& b);
    bool resolve_ref_oid(Repo& repo, std::string_view ref_spec, Oid& out);
    void flatten_tree(Repo& repo, const Oid& tree_oid, const std::string& prefix, std::map<std::string, Oid>& out);
    Oid build_tree_from_map(Repo& repo, const std::map<std::string, Oid>& files);
    bool lookup_path_in_tree(Repo& repo, const Oid& root_tree, std::string_view path, bool& is_dir, Oid& out_oid);
    Oid peel_oid(Repo& repo, const Oid& start);

    // Contents API helpers
    bool put_file_content(
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
        std::string& out_err);

    bool delete_file_content(
        Repo& repo,
        std::string_view path,
        const std::string& message,
        std::string_view branch_opt,
        std::string_view expected_sha_hex,
        Oid& out_commit_oid,
        int& out_status,
        std::string& out_err);

    // Serialization helpers
    static void append_issue_json(const Repo& repo, const Issue& issue, std::string& out);
    static void append_repo_json(const Repo& repo, std::string& out);
    static void append_pull_json(const Repo& repo, const PullRequest& pr, std::string& out);
    const std::string& get_or_build_issue_http(const Repo& repo, Issue& issue);

private:
    bool inflate_slice(const uint8_t* src, size_t max_len, size_t expected_size, std::vector<uint8_t>& out, size_t& consumed);
    bool deflate_bytes(const uint8_t* src, size_t len, std::vector<uint8_t>& out);
    static bool apply_delta(const std::vector<uint8_t>& base, const std::vector<uint8_t>& delta, std::vector<uint8_t>& out);

    std::string viewer_login_;
    std::string auth_token_;
    std::string expected_bearer_;
    int64_t base_epoch_ = 1735689600;
    uint64_t ts_counter_ = 0;
    uint64_t next_db_id_ = 1;
    uint64_t next_seq_ = 1;
    uint64_t req_counter_ = 0;

    std::unordered_map<std::string, std::unique_ptr<Repo>, TransparentStringHash, std::equal_to<>> repos_;
    std::vector<Repo*> repo_order_;
    Repo* last_repo_ = nullptr;

    std::unordered_map<uint64_t, Repo*> repo_by_db_id_;
    std::unordered_map<uint64_t, std::pair<Repo*, Issue*>> issue_by_db_id_;
    std::unordered_map<uint64_t, std::pair<Repo*, PullRequest*>> pull_by_db_id_;

    z_stream inf_{};
    z_stream def_{};
    bool inf_ready_ = false;
    bool def_ready_ = false;
};

} // namespace forge
