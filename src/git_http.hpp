#pragma once

#include "http_types.hpp"
#include "store.hpp"

namespace forge {

// Returns true if the request path matched a Git Smart HTTP route (and populated res).
bool handle_git_http(ForgeStore& store, const HttpRequest& req, HttpResponse& res);

} // namespace forge
