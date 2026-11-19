#include "graphql.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <unordered_map>

namespace forge {

namespace {

enum class GqlTokKind : uint8_t {
    Eof, Name, Int, String,
    LBrace, RBrace, LParen, RParen, LBracket, RBracket,
    Colon, Dollar, Bang, Spread, At, Equals, Invalid
};

struct GqlTok {
    GqlTokKind kind = GqlTokKind::Eof;
    std::string text;
};

class GqlLexer {
public:
    explicit GqlLexer(std::string_view src) : src_(src) {}

    GqlTok next() {
        skip_ignored();
        if (pos_ >= src_.size()) return {GqlTokKind::Eof, ""};
        char c = src_[pos_];
        if (c == '{') { ++pos_; return {GqlTokKind::LBrace, "{"}; }
        if (c == '}') { ++pos_; return {GqlTokKind::RBrace, "}"}; }
        if (c == '(') { ++pos_; return {GqlTokKind::LParen, "("}; }
        if (c == ')') { ++pos_; return {GqlTokKind::RParen, ")"}; }
        if (c == '[') { ++pos_; return {GqlTokKind::LBracket, "["}; }
        if (c == ']') { ++pos_; return {GqlTokKind::RBracket, "]"}; }
        if (c == ':') { ++pos_; return {GqlTokKind::Colon, ":"}; }
        if (c == '$') { ++pos_; return {GqlTokKind::Dollar, "$"}; }
        if (c == '!') { ++pos_; return {GqlTokKind::Bang, "!"}; }
        if (c == '@') { ++pos_; return {GqlTokKind::At, "@"}; }
        if (c == '=') { ++pos_; return {GqlTokKind::Equals, "="}; }
        if (c == '.' && pos_ + 2 < src_.size() && src_[pos_ + 1] == '.' && src_[pos_ + 2] == '.') {
            pos_ += 3;
            return {GqlTokKind::Spread, "..."};
        }
        if (c == '"') {
            ++pos_;
            std::string s;
            while (pos_ < src_.size() && src_[pos_] != '"') {
                if (src_[pos_] == '\\' && pos_ + 1 < src_.size()) {
                    ++pos_;
                    char e = src_[pos_++];
                    if (e == 'n') s.push_back('\n');
                    else if (e == 't') s.push_back('\t');
                    else if (e == 'r') s.push_back('\r');
                    else s.push_back(e);
                } else {
                    s.push_back(src_[pos_++]);
                }
            }
            if (pos_ < src_.size() && src_[pos_] == '"') ++pos_;
            return {GqlTokKind::String, std::move(s)};
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            size_t st = pos_++;
            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') ++pos_;
            return {GqlTokKind::Int, std::string(src_.substr(st, pos_ - st))};
        }
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            size_t st = pos_++;
            while (pos_ < src_.size() && (std::isalnum(static_cast<unsigned char>(src_[pos_])) || src_[pos_] == '_')) ++pos_;
            return {GqlTokKind::Name, std::string(src_.substr(st, pos_ - st))};
        }
        ++pos_;
        return {GqlTokKind::Invalid, std::string(1, c)};
    }

private:
    void skip_ignored() {
        while (pos_ < src_.size()) {
            char c = src_[pos_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',') {
                ++pos_;
            } else if (c == '#') {
                while (pos_ < src_.size() && src_[pos_] != '\n') ++pos_;
            } else {
                break;
            }
        }
    }

    std::string_view src_;
    size_t pos_ = 0;
};

struct GqlSelection;

struct GqlField {
    std::string alias;
    std::string name;
    std::vector<std::pair<std::string, JsonValue>> args;
    std::vector<GqlSelection> selections;

    const std::string& response_key() const noexcept { return alias.empty() ? name : alias; }
    const JsonValue* arg(std::string_view k) const noexcept {
        for (const auto& kv : args) if (kv.first == k) return &kv.second;
        return nullptr;
    }
};

struct GqlSelection {
    bool is_inline_fragment = false;
    std::string type_condition;
    GqlField field;
    std::vector<GqlSelection> fragment_selections;
};

struct GqlOperation {
    std::string kind = "query"; // "query" or "mutation"
    std::string name;
    std::vector<GqlSelection> selections;
};

class GqlParser {
public:
    GqlParser(std::string_view src, const JsonValue& vars) : lex_(src), vars_(vars) {
        cur_ = lex_.next();
    }

    bool parse_document(std::vector<GqlOperation>& ops, std::string& err) {
        while (cur_.kind != GqlTokKind::Eof) {
            GqlOperation op;
            if (cur_.kind == GqlTokKind::LBrace) {
                op.kind = "query";
                if (!parse_selection_set(op.selections, err)) return false;
                ops.push_back(std::move(op));
            } else if (cur_.kind == GqlTokKind::Name && (cur_.text == "query" || cur_.text == "mutation")) {
                op.kind = cur_.text;
                advance();
                if (cur_.kind == GqlTokKind::Name) {
                    op.name = cur_.text;
                    advance();
                }
                if (cur_.kind == GqlTokKind::LParen) {
                    if (!skip_var_defs(err)) return false;
                }
                if (!parse_selection_set(op.selections, err)) return false;
                ops.push_back(std::move(op));
            } else {
                err = "Unexpected token in GraphQL document: " + cur_.text;
                return false;
            }
        }
        if (ops.empty()) {
            err = "Empty GraphQL document";
            return false;
        }
        return true;
    }

private:
    void advance() { cur_ = lex_.next(); }

    bool skip_var_defs(std::string& err) {
        if (cur_.kind != GqlTokKind::LParen) return false;
        int depth = 1;
        advance();
        while (cur_.kind != GqlTokKind::Eof && depth > 0) {
            if (cur_.kind == GqlTokKind::LParen) ++depth;
            else if (cur_.kind == GqlTokKind::RParen) --depth;
            advance();
        }
        if (depth != 0) { err = "Unterminated variable definitions"; return false; }
        return true;
    }

    bool parse_value(JsonValue& out, std::string& err) {
        if (cur_.kind == GqlTokKind::Dollar) {
            advance();
            if (cur_.kind != GqlTokKind::Name) { err = "Expected variable name"; return false; }
            std::string vname = cur_.text;
            advance();
            const JsonValue* v = vars_.get(vname);
            out = v ? *v : JsonValue::make_null();
            return true;
        }
        if (cur_.kind == GqlTokKind::String) {
            out = JsonValue::make_string(cur_.text);
            advance();
            return true;
        }
        if (cur_.kind == GqlTokKind::Int) {
            out = JsonValue::make_int(std::stoll(cur_.text));
            advance();
            return true;
        }
        if (cur_.kind == GqlTokKind::Name) {
            if (cur_.text == "true") out = JsonValue::make_bool(true);
            else if (cur_.text == "false") out = JsonValue::make_bool(false);
            else if (cur_.text == "null") out = JsonValue::make_null();
            else out = JsonValue::make_string(cur_.text); // enum identifier
            advance();
            return true;
        }
        if (cur_.kind == GqlTokKind::LBracket) {
            advance();
            out = JsonValue::make_array();
            while (cur_.kind != GqlTokKind::RBracket && cur_.kind != GqlTokKind::Eof) {
                JsonValue elem;
                if (!parse_value(elem, err)) return false;
                out.arr.push_back(std::move(elem));
            }
            if (cur_.kind != GqlTokKind::RBracket) { err = "Expected ']'"; return false; }
            advance();
            return true;
        }
        if (cur_.kind == GqlTokKind::LBrace) {
            advance();
            out = JsonValue::make_object();
            while (cur_.kind != GqlTokKind::RBrace && cur_.kind != GqlTokKind::Eof) {
                if (cur_.kind != GqlTokKind::Name) { err = "Expected input field name"; return false; }
                std::string k = cur_.text;
                advance();
                if (cur_.kind != GqlTokKind::Colon) { err = "Expected ':' in input object"; return false; }
                advance();
                JsonValue v;
                if (!parse_value(v, err)) return false;
                out.obj.emplace_back(std::move(k), std::move(v));
            }
            if (cur_.kind != GqlTokKind::RBrace) { err = "Expected '}'"; return false; }
            advance();
            return true;
        }
        err = "Unexpected value token: " + cur_.text;
        return false;
    }

    bool parse_selection_set(std::vector<GqlSelection>& out, std::string& err) {
        if (cur_.kind != GqlTokKind::LBrace) { err = "Expected '{'"; return false; }
        advance();
        while (cur_.kind != GqlTokKind::RBrace && cur_.kind != GqlTokKind::Eof) {
            if (cur_.kind == GqlTokKind::Spread) {
                advance();
                GqlSelection sel;
                sel.is_inline_fragment = true;
                if (cur_.kind == GqlTokKind::Name && cur_.text == "on") {
                    advance();
                    if (cur_.kind != GqlTokKind::Name) { err = "Expected type name after 'on'"; return false; }
                    sel.type_condition = cur_.text;
                    advance();
                }
                if (!parse_selection_set(sel.fragment_selections, err)) return false;
                out.push_back(std::move(sel));
            } else if (cur_.kind == GqlTokKind::Name) {
                GqlSelection sel;
                std::string first = cur_.text;
                advance();
                if (cur_.kind == GqlTokKind::Colon) {
                    advance();
                    if (cur_.kind != GqlTokKind::Name) { err = "Expected field name after alias"; return false; }
                    sel.field.alias = std::move(first);
                    sel.field.name = cur_.text;
                    advance();
                } else {
                    sel.field.name = std::move(first);
                }
                if (cur_.kind == GqlTokKind::LParen) {
                    advance();
                    while (cur_.kind != GqlTokKind::RParen && cur_.kind != GqlTokKind::Eof) {
                        if (cur_.kind != GqlTokKind::Name) { err = "Expected argument name"; return false; }
                        std::string aname = cur_.text;
                        advance();
                        if (cur_.kind != GqlTokKind::Colon) { err = "Expected ':' after argument name"; return false; }
                        advance();
                        JsonValue aval;
                        if (!parse_value(aval, err)) return false;
                        sel.field.args.emplace_back(std::move(aname), std::move(aval));
                    }
                    if (cur_.kind != GqlTokKind::RParen) { err = "Expected ')'"; return false; }
                    advance();
                }
                if (cur_.kind == GqlTokKind::LBrace) {
                    if (!parse_selection_set(sel.field.selections, err)) return false;
                }
                out.push_back(std::move(sel));
            } else {
                err = "Unexpected token in selection set: " + cur_.text;
                return false;
            }
        }
        if (cur_.kind != GqlTokKind::RBrace) { err = "Expected '}'"; return false; }
        advance();
        return true;
    }

    GqlLexer lex_;
    const JsonValue& vars_;
    GqlTok cur_;
};

// Schema introspection tables
const std::vector<std::string>& type_fields_for(std::string_view type_name) {
    static const std::vector<std::string> kEmpty;
    static const std::vector<std::string> kIssue = {
        "id", "databaseId", "number", "title", "state", "body", "createdAt", "updatedAt", "author", "comments", "labels"
    };
    static const std::vector<std::string> kPull = {
        "id", "databaseId", "number", "title", "body", "headRefName", "baseRefName",
        "mergeable", "state", "merged", "mergedAt", "files", "createdAt", "updatedAt"
    };
    static const std::vector<std::string> kRepo = {
        "id", "databaseId", "name", "nameWithOwner", "owner", "defaultBranchRef",
        "viewerPermission", "hasIssuesEnabled", "issue", "issues", "pullRequests", "pullRequest",
        "description", "isPrivate"
    };
    static const std::vector<std::string> kUser = {"id", "login", "name"};
    if (type_name == "Issue") return kIssue;
    if (type_name == "PullRequest") return kPull;
    if (type_name == "Repository") return kRepo;
    if (type_name == "User") return kUser;
    return kEmpty;
}

const std::vector<std::string>& enum_values_for(std::string_view type_name) {
    static const std::vector<std::string> kEmpty;
    static const std::vector<std::string> kSearchType = {"ISSUE", "REPOSITORY", "USER", "DISCUSSION"};
    static const std::vector<std::string> kIssueState = {"OPEN", "CLOSED"};
    static const std::vector<std::string> kPrState = {"OPEN", "CLOSED", "MERGED"};
    static const std::vector<std::string> kMergeable = {"MERGEABLE", "CONFLICTING", "UNKNOWN"};
    static const std::vector<std::string> kMergeMethod = {"MERGE", "SQUASH", "REBASE"};
    if (type_name == "SearchType") return kSearchType;
    if (type_name == "IssueState") return kIssueState;
    if (type_name == "PullRequestState") return kPrState;
    if (type_name == "MergeableState") return kMergeable;
    if (type_name == "PullRequestMergeMethod") return kMergeMethod;
    return kEmpty;
}

void flatten_selections(const std::vector<GqlSelection>& sels, std::string_view concrete_type, std::vector<const GqlField*>& out) {
    for (const auto& s : sels) {
        if (!s.is_inline_fragment) {
            out.push_back(&s.field);
        } else if (s.type_condition.empty() || s.type_condition == concrete_type) {
            flatten_selections(s.fragment_selections, concrete_type, out);
        }
    }
}

JsonValue resolve_user(const std::string& login, const std::vector<GqlSelection>& sels, std::vector<std::string>& errors) {
    JsonValue obj = JsonValue::make_object();
    std::vector<const GqlField*> fields;
    flatten_selections(sels, "User", fields);
    for (const auto* f : fields) {
        if (f->name == "login") obj.set(f->response_key(), JsonValue::make_string(login));
        else if (f->name == "id") obj.set(f->response_key(), JsonValue::make_string("U_1000"));
        else if (f->name == "name") obj.set(f->response_key(), JsonValue::make_string(login));
        else if (f->name == "__typename") obj.set(f->response_key(), JsonValue::make_string("User"));
        else errors.push_back("Field '" + f->name + "' doesn't exist on type 'User'");
    }
    return obj;
}

JsonValue resolve_issue(const Issue& iss, const std::vector<GqlSelection>& sels, std::vector<std::string>& errors) {
    JsonValue obj = JsonValue::make_object();
    std::vector<const GqlField*> fields;
    flatten_selections(sels, "Issue", fields);
    for (const auto* f : fields) {
        if (f->name == "id") obj.set(f->response_key(), JsonValue::make_string(iss.node_id()));
        else if (f->name == "databaseId") obj.set(f->response_key(), JsonValue::make_int(static_cast<int64_t>(iss.db_id)));
        else if (f->name == "number") obj.set(f->response_key(), JsonValue::make_int(iss.number));
        else if (f->name == "title") obj.set(f->response_key(), JsonValue::make_string(iss.title));
        else if (f->name == "body") obj.set(f->response_key(), JsonValue::make_string(iss.body));
        else if (f->name == "state") obj.set(f->response_key(), JsonValue::make_string(iss.closed ? "CLOSED" : "OPEN"));
        else if (f->name == "createdAt") obj.set(f->response_key(), JsonValue::make_string(ForgeStore::format_iso8601(iss.created_epoch)));
        else if (f->name == "updatedAt") obj.set(f->response_key(), JsonValue::make_string(ForgeStore::format_iso8601(iss.updated_epoch)));
        else if (f->name == "__typename") obj.set(f->response_key(), JsonValue::make_string("Issue"));
        else errors.push_back("Field '" + f->name + "' doesn't exist on type 'Issue'");
    }
    return obj;
}

JsonValue resolve_pull(ForgeStore& store, Repo& repo, const PullRequest& pr, const std::vector<GqlSelection>& sels, std::vector<std::string>& errors) {
    JsonValue obj = JsonValue::make_object();
    std::vector<const GqlField*> fields;
    flatten_selections(sels, "PullRequest", fields);
    for (const auto* f : fields) {
        if (f->name == "id") obj.set(f->response_key(), JsonValue::make_string(pr.node_id));
        else if (f->name == "databaseId") obj.set(f->response_key(), JsonValue::make_int(static_cast<int64_t>(pr.db_id)));
        else if (f->name == "number") obj.set(f->response_key(), JsonValue::make_int(pr.number));
        else if (f->name == "title") obj.set(f->response_key(), JsonValue::make_string(pr.title));
        else if (f->name == "body") obj.set(f->response_key(), JsonValue::make_string(pr.body));
        else if (f->name == "headRefName") obj.set(f->response_key(), JsonValue::make_string(pr.head_ref));
        else if (f->name == "baseRefName") obj.set(f->response_key(), JsonValue::make_string(pr.base_ref));
        else if (f->name == "merged") obj.set(f->response_key(), JsonValue::make_bool(pr.merged));
        else if (f->name == "state") {
            std::string st = pr.merged ? "MERGED" : (pr.closed ? "CLOSED" : "OPEN");
            obj.set(f->response_key(), JsonValue::make_string(std::move(st)));
        } else if (f->name == "mergeable") {
            std::string m = pr.merged || pr.closed ? "UNKNOWN" : (store.is_pull_mergeable(repo, pr) ? "MERGEABLE" : "CONFLICTING");
            obj.set(f->response_key(), JsonValue::make_string(std::move(m)));
        } else if (f->name == "files") {
            int first = f->arg("first") ? static_cast<int>(f->arg("first")->as_int(100)) : 100;
            auto diffs = store.diff_pull(repo, pr);
            JsonValue conn = JsonValue::make_object();
            std::vector<const GqlField*> cfields;
            flatten_selections(f->selections, "PullRequestChangedFileConnection", cfields);
            for (const auto* cf : cfields) {
                if (cf->name == "nodes") {
                    JsonValue arr = JsonValue::make_array();
                    int limit = std::min<int>(first, static_cast<int>(diffs.size()));
                    for (int i = 0; i < limit; ++i) {
                        JsonValue node = JsonValue::make_object();
                        std::vector<const GqlField*> nfields;
                        flatten_selections(cf->selections, "PullRequestChangedFile", nfields);
                        for (const auto* nf : nfields) {
                            if (nf->name == "path") node.set(nf->response_key(), JsonValue::make_string(diffs[i].filename));
                            else if (nf->name == "additions") node.set(nf->response_key(), JsonValue::make_int(diffs[i].additions));
                            else if (nf->name == "deletions") node.set(nf->response_key(), JsonValue::make_int(diffs[i].deletions));
                            else errors.push_back("Field '" + nf->name + "' doesn't exist on type 'PullRequestChangedFile'");
                        }
                        arr.arr.push_back(std::move(node));
                    }
                    conn.set(cf->response_key(), std::move(arr));
                } else {
                    errors.push_back("Field '" + cf->name + "' doesn't exist on type 'PullRequestChangedFileConnection'");
                }
            }
            obj.set(f->response_key(), std::move(conn));
        } else if (f->name == "__typename") {
            obj.set(f->response_key(), JsonValue::make_string("PullRequest"));
        } else {
            errors.push_back("Field '" + f->name + "' doesn't exist on type 'PullRequest'");
        }
    }
    return obj;
}

JsonValue resolve_repo(ForgeStore& store, Repo& repo, const std::vector<GqlSelection>& sels, std::vector<std::string>& errors) {
    JsonValue obj = JsonValue::make_object();
    std::vector<const GqlField*> fields;
    flatten_selections(sels, "Repository", fields);
    for (const auto* f : fields) {
        if (f->name == "id") obj.set(f->response_key(), JsonValue::make_string(repo.node_id));
        else if (f->name == "databaseId") obj.set(f->response_key(), JsonValue::make_int(static_cast<int64_t>(repo.db_id)));
        else if (f->name == "name") obj.set(f->response_key(), JsonValue::make_string(repo.name));
        else if (f->name == "nameWithOwner") obj.set(f->response_key(), JsonValue::make_string(repo.owner + "/" + repo.name));
        else if (f->name == "description") obj.set(f->response_key(), JsonValue::make_string(repo.description));
        else if (f->name == "isPrivate") obj.set(f->response_key(), JsonValue::make_bool(repo.is_private));
        else if (f->name == "viewerPermission") obj.set(f->response_key(), JsonValue::make_string("ADMIN"));
        else if (f->name == "hasIssuesEnabled") obj.set(f->response_key(), JsonValue::make_bool(true));
        else if (f->name == "__typename") obj.set(f->response_key(), JsonValue::make_string("Repository"));
        else if (f->name == "owner") {
            obj.set(f->response_key(), resolve_user(repo.owner, f->selections, errors));
        } else if (f->name == "defaultBranchRef") {
            auto it = repo.refs.find("refs/heads/" + repo.default_branch);
            if (it == repo.refs.end()) {
                obj.set(f->response_key(), JsonValue::make_null());
            } else {
                JsonValue ref = JsonValue::make_object();
                std::vector<const GqlField*> rfields;
                flatten_selections(f->selections, "Ref", rfields);
                for (const auto* rf : rfields) {
                    if (rf->name == "name") ref.set(rf->response_key(), JsonValue::make_string(repo.default_branch));
                    else if (rf->name == "prefix") ref.set(rf->response_key(), JsonValue::make_string("refs/heads/"));
                    else errors.push_back("Field '" + rf->name + "' doesn't exist on type 'Ref'");
                }
                obj.set(f->response_key(), std::move(ref));
            }
        } else if (f->name == "issue") {
            int num = f->arg("number") ? static_cast<int>(f->arg("number")->as_int(0)) : 0;
            Issue* iss = repo.find_issue(static_cast<uint32_t>(num));
            if (!iss) {
                obj.set(f->response_key(), JsonValue::make_null());
            } else {
                obj.set(f->response_key(), resolve_issue(*iss, f->selections, errors));
            }
        } else if (f->name == "issues") {
            int first = f->arg("first") ? static_cast<int>(f->arg("first")->as_int(100)) : 100;
            bool filter_open = false, filter_closed = false, has_states = false;
            if (const auto* sv = f->arg("states"); sv && sv->is_array() && !sv->arr.empty()) {
                has_states = true;
                for (const auto& e : sv->arr) {
                    if (e.is_string() && e.s == "OPEN") filter_open = true;
                    if (e.is_string() && e.s == "CLOSED") filter_closed = true;
                }
            }
            bool desc = false;
            if (const auto* ob = f->arg("orderBy"); ob && ob->is_object()) {
                if (const auto* dir = ob->get("direction"); dir && dir->is_string() && dir->s == "DESC") desc = true;
            }
            size_t start_idx = 0;
            if (const auto* after = f->arg("after"); after && after->is_string() && !after->s.empty()) {
                if (after->s.substr(0, 4) == "cur_") {
                    start_idx = static_cast<size_t>(std::stoul(after->s.substr(4))) + 1;
                }
            }

            std::vector<const Issue*> list;
            list.reserve(repo.issues.size());
            for (const auto& up : repo.issues) {
                if (has_states) {
                    if (!up->closed && !filter_open) continue;
                    if (up->closed && !filter_closed) continue;
                }
                list.push_back(up.get());
            }
            if (desc) {
                std::sort(list.begin(), list.end(), [](const Issue* a, const Issue* b) {
                    if (a->created_seq != b->created_seq) return a->created_seq > b->created_seq;
                    return a->number > b->number;
                });
            } else {
                std::sort(list.begin(), list.end(), [](const Issue* a, const Issue* b) {
                    if (a->created_seq != b->created_seq) return a->created_seq < b->created_seq;
                    return a->number < b->number;
                });
            }

            size_t end_idx = std::min(list.size(), start_idx + static_cast<size_t>(std::max(0, first)));
            bool has_next = (end_idx < list.size());
            std::string end_cursor = (end_idx > start_idx) ? ("cur_" + std::to_string(end_idx - 1)) : "";

            JsonValue conn = JsonValue::make_object();
            std::vector<const GqlField*> cfields;
            flatten_selections(f->selections, "IssueConnection", cfields);
            for (const auto* cf : cfields) {
                if (cf->name == "nodes") {
                    JsonValue arr = JsonValue::make_array();
                    for (size_t i = start_idx; i < end_idx; ++i) {
                        arr.arr.push_back(resolve_issue(*list[i], cf->selections, errors));
                    }
                    conn.set(cf->response_key(), std::move(arr));
                } else if (cf->name == "pageInfo") {
                    JsonValue pi = JsonValue::make_object();
                    std::vector<const GqlField*> pfields;
                    flatten_selections(cf->selections, "PageInfo", pfields);
                    for (const auto* pf : pfields) {
                        if (pf->name == "hasNextPage") pi.set(pf->response_key(), JsonValue::make_bool(has_next));
                        else if (pf->name == "endCursor") {
                            pi.set(pf->response_key(), end_cursor.empty() ? JsonValue::make_null() : JsonValue::make_string(end_cursor));
                        } else if (pf->name == "hasPreviousPage") pi.set(pf->response_key(), JsonValue::make_bool(start_idx > 0));
                        else errors.push_back("Field '" + pf->name + "' doesn't exist on type 'PageInfo'");
                    }
                    conn.set(cf->response_key(), std::move(pi));
                } else if (cf->name == "totalCount") {
                    conn.set(cf->response_key(), JsonValue::make_int(static_cast<int64_t>(list.size())));
                } else {
                    errors.push_back("Field '" + cf->name + "' doesn't exist on type 'IssueConnection'");
                }
            }
            obj.set(f->response_key(), std::move(conn));
        } else if (f->name == "pullRequest") {
            int num = f->arg("number") ? static_cast<int>(f->arg("number")->as_int(0)) : 0;
            auto it = repo.pull_by_number.find(static_cast<uint32_t>(num));
            if (it == repo.pull_by_number.end()) {
                obj.set(f->response_key(), JsonValue::make_null());
            } else {
                obj.set(f->response_key(), resolve_pull(store, repo, *it->second, f->selections, errors));
            }
        } else if (f->name == "pullRequests") {
            int first = f->arg("first") ? static_cast<int>(f->arg("first")->as_int(100)) : 100;
            std::vector<const PullRequest*> list;
            for (const auto& up : repo.pulls) list.push_back(up.get());
            std::sort(list.begin(), list.end(), [](const PullRequest* a, const PullRequest* b) {
                return a->created_seq > b->created_seq;
            });
            size_t end_idx = std::min(list.size(), static_cast<size_t>(std::max(0, first)));
            JsonValue conn = JsonValue::make_object();
            std::vector<const GqlField*> cfields;
            flatten_selections(f->selections, "PullRequestConnection", cfields);
            for (const auto* cf : cfields) {
                if (cf->name == "nodes") {
                    JsonValue arr = JsonValue::make_array();
                    for (size_t i = 0; i < end_idx; ++i) {
                        arr.arr.push_back(resolve_pull(store, repo, *list[i], cf->selections, errors));
                    }
                    conn.set(cf->response_key(), std::move(arr));
                } else if (cf->name == "totalCount") {
                    conn.set(cf->response_key(), JsonValue::make_int(static_cast<int64_t>(list.size())));
                } else {
                    errors.push_back("Field '" + cf->name + "' doesn't exist on type 'PullRequestConnection'");
                }
            }
            obj.set(f->response_key(), std::move(conn));
        } else {
            errors.push_back("Field '" + f->name + "' doesn't exist on type 'Repository'");
        }
    }
    return obj;
}

JsonValue resolve_introspection_type(std::string_view type_name, const std::vector<GqlSelection>& sels, std::vector<std::string>& errors) {
    JsonValue obj = JsonValue::make_object();
    std::vector<const GqlField*> fields;
    flatten_selections(sels, "__Type", fields);
    for (const auto* f : fields) {
        if (f->name == "name") {
            obj.set(f->response_key(), JsonValue::make_string(std::string(type_name)));
        } else if (f->name == "fields") {
            const auto& names = type_fields_for(type_name);
            JsonValue arr = JsonValue::make_array();
            for (const auto& n : names) {
                JsonValue fi = JsonValue::make_object();
                std::vector<const GqlField*> sfields;
                flatten_selections(f->selections, "__Field", sfields);
                for (const auto* sf : sfields) {
                    if (sf->name == "name") fi.set(sf->response_key(), JsonValue::make_string(n));
                    else if (sf->name == "isDeprecated") fi.set(sf->response_key(), JsonValue::make_bool(false));
                }
                arr.arr.push_back(std::move(fi));
            }
            obj.set(f->response_key(), std::move(arr));
        } else if (f->name == "enumValues") {
            const auto& vals = enum_values_for(type_name);
            JsonValue arr = JsonValue::make_array();
            for (const auto& v : vals) {
                JsonValue ei = JsonValue::make_object();
                std::vector<const GqlField*> sfields;
                flatten_selections(f->selections, "__EnumValue", sfields);
                for (const auto* sf : sfields) {
                    if (sf->name == "name") ei.set(sf->response_key(), JsonValue::make_string(v));
                    else if (sf->name == "isDeprecated") ei.set(sf->response_key(), JsonValue::make_bool(false));
                }
                arr.arr.push_back(std::move(ei));
            }
            obj.set(f->response_key(), std::move(arr));
        } else {
            errors.push_back("Field '" + f->name + "' doesn't exist on type '__Type'");
        }
    }
    return obj;
}

JsonValue execute_single(ForgeStore& store, const JsonValue& req_obj) {
    const auto* qv = req_obj.get("query");
    if (!qv || !qv->is_string()) {
        JsonValue r = JsonValue::make_object();
        JsonValue errs = JsonValue::make_array();
        JsonValue e = JsonValue::make_object();
        e.set("message", JsonValue::make_string("Missing query string"));
        errs.arr.push_back(std::move(e));
        r.set("errors", std::move(errs));
        return r;
    }
    JsonValue empty_vars = JsonValue::make_object();
    const JsonValue& vars = (req_obj.get("variables") && req_obj.get("variables")->is_object())
                                ? *req_obj.get("variables")
                                : empty_vars;
    std::string op_name = req_obj.get("operationName") ? req_obj.get("operationName")->as_string("") : "";

    GqlParser parser(qv->s, vars);
    std::vector<GqlOperation> ops;
    std::string parse_err;
    if (!parser.parse_document(ops, parse_err)) {
        JsonValue r = JsonValue::make_object();
        JsonValue errs = JsonValue::make_array();
        JsonValue e = JsonValue::make_object();
        e.set("message", JsonValue::make_string(parse_err));
        errs.arr.push_back(std::move(e));
        r.set("errors", std::move(errs));
        return r;
    }

    const GqlOperation* chosen = &ops[0];
    if (!op_name.empty()) {
        for (const auto& op : ops) {
            if (op.name == op_name) { chosen = &op; break; }
        }
    }

    std::vector<std::string> errors;
    JsonValue data = JsonValue::make_object();

    if (chosen->kind == "query") {
        std::vector<const GqlField*> fields;
        flatten_selections(chosen->selections, "Query", fields);
        for (const auto* f : fields) {
            if (f->name == "viewer") {
                data.set(f->response_key(), resolve_user(store.viewer_login(), f->selections, errors));
            } else if (f->name == "repository") {
                std::string owner = f->arg("owner") ? f->arg("owner")->as_string("") : "";
                std::string name = f->arg("name") ? f->arg("name")->as_string("") : "";
                Repo* repo = store.find_repo(owner, name);
                if (!repo) data.set(f->response_key(), JsonValue::make_null());
                else data.set(f->response_key(), resolve_repo(store, *repo, f->selections, errors));
            } else if (f->name == "__type") {
                std::string tname = f->arg("name") ? f->arg("name")->as_string("") : "";
                data.set(f->response_key(), resolve_introspection_type(tname, f->selections, errors));
            } else if (f->name == "node") {
                std::string nid = f->arg("id") ? f->arg("id")->as_string("") : "";
                NodeLookup nl{};
                if (!store.find_node(nid, nl)) {
                    data.set(f->response_key(), JsonValue::make_null());
                } else if (nl.kind == NodeLookup::Kind::Repo && nl.repo) {
                    data.set(f->response_key(), resolve_repo(store, *nl.repo, f->selections, errors));
                } else if (nl.kind == NodeLookup::Kind::Issue && nl.issue) {
                    data.set(f->response_key(), resolve_issue(*nl.issue, f->selections, errors));
                } else if (nl.kind == NodeLookup::Kind::PullRequest && nl.pull && nl.repo) {
                    data.set(f->response_key(), resolve_pull(store, *nl.repo, *nl.pull, f->selections, errors));
                } else {
                    data.set(f->response_key(), JsonValue::make_null());
                }
            } else {
                errors.push_back("Field '" + f->name + "' doesn't exist on type 'Query'");
            }
        }
    } else {
        // Mutation
        std::vector<const GqlField*> fields;
        flatten_selections(chosen->selections, "Mutation", fields);
        for (const auto* f : fields) {
            const JsonValue* inp = f->arg("input");
            if (f->name == "createIssue") {
                if (!inp || !inp->is_object()) { errors.push_back("Missing input for createIssue"); continue; }
                std::string rid = inp->get("repositoryId") ? inp->get("repositoryId")->as_string("") : "";
                std::string title = inp->get("title") ? inp->get("title")->as_string("") : "";
                std::string body = inp->get("body") ? inp->get("body")->as_string("") : "";
                NodeLookup nl{};
                if (!store.find_node(rid, nl) || nl.kind != NodeLookup::Kind::Repo || !nl.repo) {
                    errors.push_back("Repository not found for repositoryId");
                    continue;
                }
                std::string err;
                Issue* iss = store.create_issue(*nl.repo, std::move(title), std::move(body), {}, err);
                if (!iss) { errors.push_back(err); continue; }
                JsonValue payload = JsonValue::make_object();
                std::vector<const GqlField*> pfields;
                flatten_selections(f->selections, "CreateIssuePayload", pfields);
                for (const auto* pf : pfields) {
                    if (pf->name == "issue") payload.set(pf->response_key(), resolve_issue(*iss, pf->selections, errors));
                }
                data.set(f->response_key(), std::move(payload));
            } else if (f->name == "closeIssue") {
                if (!inp || !inp->is_object()) { errors.push_back("Missing input for closeIssue"); continue; }
                std::string iid = inp->get("issueId") ? inp->get("issueId")->as_string("") : "";
                NodeLookup nl{};
                if (!store.find_node(iid, nl) || nl.kind != NodeLookup::Kind::Issue || !nl.issue) {
                    errors.push_back("Issue not found for issueId");
                    continue;
                }
                nl.issue->closed = true;
                nl.issue->updated_epoch = store.next_commit_epoch();
                nl.issue->cached_http_response.clear();
                JsonValue payload = JsonValue::make_object();
                std::vector<const GqlField*> pfields;
                flatten_selections(f->selections, "CloseIssuePayload", pfields);
                for (const auto* pf : pfields) {
                    if (pf->name == "issue") payload.set(pf->response_key(), resolve_issue(*nl.issue, pf->selections, errors));
                }
                data.set(f->response_key(), std::move(payload));
            } else if (f->name == "createPullRequest") {
                if (!inp || !inp->is_object()) { errors.push_back("Missing input for createPullRequest"); continue; }
                std::string rid = inp->get("repositoryId") ? inp->get("repositoryId")->as_string("") : "";
                std::string head = inp->get("headRefName") ? inp->get("headRefName")->as_string("") : "";
                std::string base = inp->get("baseRefName") ? inp->get("baseRefName")->as_string("") : "";
                std::string title = inp->get("title") ? inp->get("title")->as_string("") : "";
                std::string body = inp->get("body") ? inp->get("body")->as_string("") : "";
                NodeLookup nl{};
                if (!store.find_node(rid, nl) || nl.kind != NodeLookup::Kind::Repo || !nl.repo) {
                    errors.push_back("Repository not found for repositoryId");
                    continue;
                }
                std::string err;
                PullRequest* pr = store.create_pull(*nl.repo, std::move(title), std::move(body), head, base, err);
                if (!pr) { errors.push_back(err); continue; }
                JsonValue payload = JsonValue::make_object();
                std::vector<const GqlField*> pfields;
                flatten_selections(f->selections, "CreatePullRequestPayload", pfields);
                for (const auto* pf : pfields) {
                    if (pf->name == "pullRequest") payload.set(pf->response_key(), resolve_pull(store, *nl.repo, *pr, pf->selections, errors));
                }
                data.set(f->response_key(), std::move(payload));
            } else if (f->name == "mergePullRequest") {
                if (!inp || !inp->is_object()) { errors.push_back("Missing input for mergePullRequest"); continue; }
                std::string pid = inp->get("pullRequestId") ? inp->get("pullRequestId")->as_string("") : "";
                std::string method = inp->get("mergeMethod") ? inp->get("mergeMethod")->as_string("SQUASH") : "SQUASH";
                std::string mlow;
                for (char c : method) mlow.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
                NodeLookup nl{};
                if (!store.find_node(pid, nl) || nl.kind != NodeLookup::Kind::PullRequest || !nl.pull || !nl.repo) {
                    errors.push_back("PullRequest not found for pullRequestId");
                    continue;
                }
                Oid sha{};
                std::string err;
                int st = 200;
                if (!store.merge_pull(*nl.repo, *nl.pull, mlow, sha, err, st)) {
                    errors.push_back(err);
                    continue;
                }
                JsonValue payload = JsonValue::make_object();
                std::vector<const GqlField*> pfields;
                flatten_selections(f->selections, "MergePullRequestPayload", pfields);
                for (const auto* pf : pfields) {
                    if (pf->name == "pullRequest") payload.set(pf->response_key(), resolve_pull(store, *nl.repo, *nl.pull, pf->selections, errors));
                }
                data.set(f->response_key(), std::move(payload));
            } else if (f->name == "addComment") {
                if (!inp || !inp->is_object()) { errors.push_back("Missing input for addComment"); continue; }
                std::string sid = inp->get("subjectId") ? inp->get("subjectId")->as_string("") : "";
                std::string body = inp->get("body") ? inp->get("body")->as_string("") : "";
                NodeLookup nl{};
                if (!store.find_node(sid, nl) || nl.kind != NodeLookup::Kind::Issue || !nl.issue || !nl.repo) {
                    errors.push_back("Subject not found for subjectId");
                    continue;
                }
                Comment* c = store.add_comment(*nl.repo, *nl.issue, std::move(body));
                JsonValue payload = JsonValue::make_object();
                std::vector<const GqlField*> pfields;
                flatten_selections(f->selections, "AddCommentPayload", pfields);
                for (const auto* pf : pfields) {
                    if (pf->name == "commentEdge") {
                        JsonValue edge = JsonValue::make_object();
                        std::vector<const GqlField*> efields;
                        flatten_selections(pf->selections, "IssueCommentEdge", efields);
                        for (const auto* ef : efields) {
                            if (ef->name == "node") {
                                JsonValue node = JsonValue::make_object();
                                std::vector<const GqlField*> nfields;
                                flatten_selections(ef->selections, "IssueComment", nfields);
                                for (const auto* nf : nfields) {
                                    if (nf->name == "id") node.set(nf->response_key(), JsonValue::make_string(c->node_id));
                                    else if (nf->name == "body") node.set(nf->response_key(), JsonValue::make_string(c->body));
                                }
                                edge.set(ef->response_key(), std::move(node));
                            }
                        }
                        payload.set(pf->response_key(), std::move(edge));
                    }
                }
                data.set(f->response_key(), std::move(payload));
            } else {
                errors.push_back("Field '" + f->name + "' doesn't exist on type 'Mutation'");
            }
        }
    }

    JsonValue resp = JsonValue::make_object();
    if (!errors.empty()) {
        JsonValue errs = JsonValue::make_array();
        for (const auto& msg : errors) {
            JsonValue e = JsonValue::make_object();
            e.set("message", JsonValue::make_string(msg));
            errs.arr.push_back(std::move(e));
        }
        resp.set("errors", std::move(errs));
        resp.set("data", std::move(data));
    } else {
        resp.set("data", std::move(data));
    }
    return resp;
}

} // namespace

bool handle_graphql(ForgeStore& store, const HttpRequest& req, HttpResponse& res) {
    if (req.path != "/api/graphql") return false;
    if (!store.check_auth(req.authorization)) {
        build_error_json(res, 401, "Requires authentication", store.next_request_id(), req.keep_alive);
        return true;
    }
    if (req.method != "POST") {
        build_error_json(res, 405, "Method Not Allowed", store.next_request_id(), req.keep_alive);
        return true;
    }
    JsonValue body;
    if (!parse_json(req.body, body)) {
        build_error_json(res, 400, "Problems parsing JSON", store.next_request_id(), req.keep_alive);
        return true;
    }
    if (body.is_array()) {
        JsonValue out = JsonValue::make_array();
        for (const auto& op : body.arr) {
            out.arr.push_back(execute_single(store, op));
        }
        build_json_response(res, 200, to_json(out), store.next_request_id(), req.keep_alive);
        return true;
    }
    if (body.is_object()) {
        JsonValue out = execute_single(store, body);
        build_json_response(res, 200, to_json(out), store.next_request_id(), req.keep_alive);
        return true;
    }
    build_error_json(res, 400, "Invalid GraphQL payload", store.next_request_id(), req.keep_alive);
    return true;
}

} // namespace forge
