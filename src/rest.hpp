#pragma once

#include "http_types.hpp"
#include "store.hpp"

namespace forge {

// Zero-allocation read-only fast path (safe under shared_lock). Returns true on cache hit.
bool try_rest_fast_readonly(const ForgeStore& store, const HttpRequest& req, HttpResponse& res);

// Handles all /api/v3* routes. Returns true if matched.
bool handle_rest(ForgeStore& store, const HttpRequest& req, HttpResponse& res);

} // namespace forge
