#include "mcp.hpp"

#include <algorithm>
#include <cctype>

namespace forge {

namespace {

static constexpr std::string_view kToolsListJson =
    "{\"tools\":["
    "{\"name\":\"create_repo\",\"description\":\"Create a new repository for the authenticated user\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
    "\"name\":{\"type\":\"string\",\"description\":\"Repository name\"},"
    "\"description\":{\"type\":\"string\",\"description\":\"Repository description\"},"
    "\"private\":{\"type\":\"boolean\",\"description\":\"Whether the repository is private\"}"
    "},\"required\":[\"name\"]}},"
    "{\"name\":\"get_repo\",\"description\":\"Get a repository by owner and name\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
    "\"owner\":{\"type\":\"string\",\"description\":\"Repository owner login\"},"
    "\"repo\":{\"type\":\"string\",\"description\":\"Repository name\"}"
    "},\"required\":[\"owner\",\"repo\"]}},"
    "{\"name\":\"create_issue\",\"description\":\"Create a new issue in a repository\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
    "\"owner\":{\"type\":\"string\",\"description\":\"Repository owner login\"},"
    "\"repo\":{\"type\":\"string\",\"description\":\"Repository name\"},"
    "\"title\":{\"type\":\"string\",\"description\":\"Issue title\"},"
    "\"body\":{\"type\":\"string\",\"description\":\"Issue body\"}"
    "},\"required\":[\"owner\",\"repo\",\"title\"]}},"
    "{\"name\":\"list_issues\",\"description\":\"List issues in a repository\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
    "\"owner\":{\"type\":\"string\",\"description\":\"Repository owner login\"},"
    "\"repo\":{\"type\":\"string\",\"description\":\"Repository name\"},"
    "\"state\":{\"type\":\"string\",\"description\":\"Filter by state: open, closed, or all\"}"
    "},\"required\":[\"owner\",\"repo\"]}},"
    "{\"name\":\"create_pull_request\",\"description\":\"Open a pull request between two branches\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
    "\"owner\":{\"type\":\"string\",\"description\":\"Repository owner login\"},"
    "\"repo\":{\"type\":\"string\",\"description\":\"Repository name\"},"
    "\"title\":{\"type\":\"string\",\"description\":\"Pull request title\"},"
    "\"body\":{\"type\":\"string\",\"description\":\"Pull request body\"},"
    "\"head\":{\"type\":\"string\",\"description\":\"Source branch name\"},"
    "\"base\":{\"type\":\"string\",\"description\":\"Target branch name\"}"
    "},\"required\":[\"owner\",\"repo\",\"title\",\"head\",\"base\"]}},"
    "{\"name\":\"merge_pull_request\",\"description\":\"Merge an open pull request\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
    "\"owner\":{\"type\":\"string\",\"description\":\"Repository owner login\"},"
    "\"repo\":{\"type\":\"string\",\"description\":\"Repository name\"},"
    "\"pull_number\":{\"type\":\"integer\",\"description\":\"Pull request number\"},"
    "\"merge_method\":{\"type\":\"string\",\"description\":\"Merge method: squash, merge, or rebase\"}"
    "},\"required\":[\"owner\",\"repo\",\"pull_number\"]}}"
    "]}";

void send_rpc_result(ForgeStore& store, const HttpRequest& req, HttpResponse& res, const JsonValue* id, std::string_view result_json) {
    std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
    if (id) serialize_json(*id, out);
    else out += "null";
    out += ",\"result\":";
    out += result_json;
    out += "}";
    build_json_response(res, 200, out, store.next_request_id(), req.keep_alive);
}

void send_rpc_error(ForgeStore& store, const HttpRequest& req, HttpResponse& res, int http_status, const JsonValue* id, int code, std::string_view msg) {
    std::string out = "{\"jsonrpc\":\"2.0\",\"id\":";
    if (id) serialize_json(*id, out);
    else out += "null";
    out += ",\"error\":{\"code\":";
    out += std::to_string(code);
    out += ",\"message\":";
    append_json_escaped(out, msg);
    out += "}}";
    build_json_response(res, http_status, out, store.next_request_id(), req.keep_alive);
}

void send_tool_ok(ForgeStore& store, const HttpRequest& req, HttpResponse& res, const JsonValue* id, std::string_view payload_json) {
    std::string r = "{\"content\":[{\"type\":\"text\",\"text\":";
    append_json_escaped(r, payload_json);
    r += "}],\"structuredContent\":";
    r += payload_json;
    r += ",\"isError\":false}";
    send_rpc_result(store, req, res, id, r);
}

void send_tool_err(ForgeStore& store, const HttpRequest& req, HttpResponse& res, const JsonValue* id, std::string_view msg) {
    std::string r = "{\"content\":[{\"type\":\"text\",\"text\":";
    append_json_escaped(r, msg);
    r += "}],\"isError\":true}";
    send_rpc_result(store, req, res, id, r);
}

} // namespace

bool handle_mcp(ForgeStore& store, const HttpRequest& req, HttpResponse& res) {
    if (req.path != "/mcp") return false;

    if (req.method == "DELETE") {
        build_http_response(res, 200, "application/json; charset=utf-8", "{\"ok\":true}", store.next_request_id(), req.keep_alive);
        return true;
    }

    if (!store.check_auth(req.authorization)) {
        build_error_json(res, 401, "Requires authentication", store.next_request_id(), req.keep_alive);
        return true;
    }

    if (req.method != "POST") {
        build_error_json(res, 405, "Method Not Allowed", store.next_request_id(), req.keep_alive);
        return true;
    }

    JsonValue rpc;
    if (!parse_json(req.body, rpc) || !rpc.is_object()) {
        send_rpc_error(store, req, res, 400, nullptr, -32700, "Parse error");
        return true;
    }

    const JsonValue* id = rpc.get("id");
    const JsonValue* method_v = rpc.get("method");
    if (!method_v || !method_v->is_string()) {
        send_rpc_error(store, req, res, 400, id, -32600, "Invalid Request");
        return true;
    }
    const std::string& method = method_v->s;

    if (method == "server/discover") {
        static constexpr std::string_view kDiscover =
            "{\"supportedVersions\":[\"2026-07-28\",\"2025-11-25\",\"2025-06-18\"],"
            "\"serverInfo\":{\"name\":\"cobalt-forge\",\"version\":\"1.0.0\"},"
            "\"capabilities\":{\"tools\":{}},"
            "\"_meta\":{\"io.modelcontextprotocol/serverInfo\":{\"name\":\"cobalt-forge\",\"version\":\"1.0.0\"}}}";
        send_rpc_result(store, req, res, id, kDiscover);
        return true;
    }

    if (method == "initialize") {
        std::string proto = "2025-11-25";
        if (const auto* params = rpc.get("params"); params && params->is_object()) {
            if (const auto* pv = params->get("protocolVersion"); pv && pv->is_string() && !pv->s.empty()) {
                proto = pv->s;
            }
        }
        std::string out = "{\"protocolVersion\":";
        append_json_escaped(out, proto);
        out += ",\"serverInfo\":{\"name\":\"cobalt-forge\",\"version\":\"1.0.0\"},\"capabilities\":{\"tools\":{}}}";
        send_rpc_result(store, req, res, id, out);
        return true;
    }

    if (method == "notifications/initialized" || id == nullptr) {
        build_http_response(res, 202, "application/json; charset=utf-8", "", store.next_request_id(), req.keep_alive);
        return true;
    }

    if (method == "tools/list") {
        send_rpc_result(store, req, res, id, kToolsListJson);
        return true;
    }

    if (method == "tools/call") {
        const JsonValue* params = rpc.get("params");
        if (!params || !params->is_object()) {
            send_rpc_error(store, req, res, 200, id, -32602, "Missing params");
            return true;
        }
        const JsonValue* name_v = params->get("name");
        if (!name_v || !name_v->is_string() || name_v->s.empty()) {
            send_rpc_error(store, req, res, 200, id, -32602, "Missing tool name");
            return true;
        }
        const std::string& tname = name_v->s;
        JsonValue empty_args = JsonValue::make_object();
        const JsonValue& args = (params->get("arguments") && params->get("arguments")->is_object())
                                    ? *params->get("arguments")
                                    : empty_args;

        if (tname == "create_repo") {
            const auto* n = args.get("name");
            if (!n || !n->is_string() || n->s.empty()) {
                send_rpc_error(store, req, res, 200, id, -32602, "Missing required argument: name");
                return true;
            }
            bool priv = args.get("private") ? args.get("private")->as_bool(false) : false;
            std::string desc = args.get("description") ? args.get("description")->as_string("") : "";
            Repo* repo = store.create_repo(n->s, priv, desc);
            if (!repo) {
                send_tool_err(store, req, res, id, "Repository already exists");
                return true;
            }
            std::string json;
            ForgeStore::append_repo_json(*repo, json);
            send_tool_ok(store, req, res, id, json);
            return true;
        }

        if (tname == "get_repo") {
            const auto* o = args.get("owner");
            const auto* r = args.get("repo");
            if (!o || !o->is_string() || o->s.empty() || !r || !r->is_string() || r->s.empty()) {
                send_rpc_error(store, req, res, 200, id, -32602, "Missing required arguments: owner, repo");
                return true;
            }
            Repo* repo = store.find_repo(o->s, r->s);
            if (!repo) {
                send_tool_err(store, req, res, id, "Repository not found");
                return true;
            }
            std::string json;
            ForgeStore::append_repo_json(*repo, json);
            send_tool_ok(store, req, res, id, json);
            return true;
        }

        if (tname == "create_issue") {
            const auto* o = args.get("owner");
            const auto* r = args.get("repo");
            const auto* t = args.get("title");
            if (!o || !o->is_string() || o->s.empty() ||
                !r || !r->is_string() || r->s.empty() ||
                !t || !t->is_string() || t->s.empty()) {
                send_rpc_error(store, req, res, 200, id, -32602, "Missing required arguments: owner, repo, title");
                return true;
            }
            Repo* repo = store.find_repo(o->s, r->s);
            if (!repo) {
                send_tool_err(store, req, res, id, "Repository not found");
                return true;
            }
            std::string ibody = args.get("body") ? args.get("body")->as_string("") : "";
            std::string err;
            Issue* iss = store.create_issue(*repo, t->s, std::move(ibody), {}, err);
            if (!iss) {
                send_tool_err(store, req, res, id, err);
                return true;
            }
            std::string json;
            ForgeStore::append_issue_json(*repo, *iss, json);
            send_tool_ok(store, req, res, id, json);
            return true;
        }

        if (tname == "list_issues") {
            const auto* o = args.get("owner");
            const auto* r = args.get("repo");
            if (!o || !o->is_string() || o->s.empty() || !r || !r->is_string() || r->s.empty()) {
                send_rpc_error(store, req, res, 200, id, -32602, "Missing required arguments: owner, repo");
                return true;
            }
            Repo* repo = store.find_repo(o->s, r->s);
            if (!repo) {
                send_tool_err(store, req, res, id, "Repository not found");
                return true;
            }
            std::string state = args.get("state") ? args.get("state")->as_string("open") : "open";
            std::string json = "[";
            bool first = true;
            for (const auto& iss : repo->issues) {
                if (state == "open" && iss.closed) continue;
                if (state == "closed" && !iss.closed) continue;
                if (!first) json.push_back(',');
                first = false;
                ForgeStore::append_issue_json(*repo, iss, json);
            }
            json.push_back(']');
            send_tool_ok(store, req, res, id, json);
            return true;
        }

        if (tname == "create_pull_request") {
            const auto* o = args.get("owner");
            const auto* r = args.get("repo");
            const auto* t = args.get("title");
            const auto* h = args.get("head");
            const auto* b = args.get("base");
            if (!o || !o->is_string() || o->s.empty() ||
                !r || !r->is_string() || r->s.empty() ||
                !t || !t->is_string() || t->s.empty() ||
                !h || !h->is_string() || h->s.empty() ||
                !b || !b->is_string() || b->s.empty()) {
                send_rpc_error(store, req, res, 200, id, -32602, "Missing required arguments: owner, repo, title, head, base");
                return true;
            }
            Repo* repo = store.find_repo(o->s, r->s);
            if (!repo) {
                send_tool_err(store, req, res, id, "Repository not found");
                return true;
            }
            std::string pbody = args.get("body") ? args.get("body")->as_string("") : "";
            std::string err;
            PullRequest* pr = store.create_pull(*repo, t->s, std::move(pbody), h->s, b->s, err);
            if (!pr) {
                send_tool_err(store, req, res, id, err);
                return true;
            }
            std::string json;
            ForgeStore::append_pull_json(*repo, *pr, json);
            send_tool_ok(store, req, res, id, json);
            return true;
        }

        if (tname == "merge_pull_request") {
            const auto* o = args.get("owner");
            const auto* r = args.get("repo");
            const auto* n = args.get("pull_number");
            if (!o || !o->is_string() || o->s.empty() ||
                !r || !r->is_string() || r->s.empty() ||
                !n || !n->is_number()) {
                send_rpc_error(store, req, res, 200, id, -32602, "Missing required arguments: owner, repo, pull_number");
                return true;
            }
            Repo* repo = store.find_repo(o->s, r->s);
            if (!repo) {
                send_tool_err(store, req, res, id, "Repository not found");
                return true;
            }
            auto it = repo->pull_by_number.find(static_cast<uint32_t>(n->as_int(0)));
            if (it == repo->pull_by_number.end()) {
                send_tool_err(store, req, res, id, "Pull request not found");
                return true;
            }
            std::string mm = args.get("merge_method") ? args.get("merge_method")->as_string("squash") : "squash";
            Oid sha{};
            std::string err;
            int st = 200;
            if (!store.merge_pull(*repo, *it->second, mm, sha, err, st)) {
                send_tool_err(store, req, res, id, err);
                return true;
            }
            std::string json = "{\"sha\":";
            append_json_escaped(json, sha.hex());
            json += ",\"merged\":true,\"message\":\"Pull Request successfully merged\"}";
            send_tool_ok(store, req, res, id, json);
            return true;
        }

        send_rpc_error(store, req, res, 200, id, -32601, "Unknown tool: " + tname);
        return true;
    }

    send_rpc_error(store, req, res, 200, id, -32601, "Method not found: " + method);
    return true;
}

} // namespace forge
