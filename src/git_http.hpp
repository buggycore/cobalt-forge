#pragma once

#include "http_types.hpp"
#include "store.hpp"

namespace forge {

// Zero-allocation read-only fast path (safe under shared_lock). Returns true on cache hit.
bool try_git_fast_readonly(const ForgeStore& store, const HttpRequest& req, HttpResponse& res);

// Returns true if the request path matched a Git Smart HTTP route (and populated res).
bool handle_git_http(ForgeStore& store, const HttpRequest& req, HttpResponse& res);

} // namespace forge
