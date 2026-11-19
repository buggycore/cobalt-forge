#pragma once

#include "http_types.hpp"
#include "store.hpp"

namespace forge {

// Handles /mcp Streamable HTTP JSON-RPC 2.0 endpoint. Returns true if path matched.
bool handle_mcp(ForgeStore& store, const HttpRequest& req, HttpResponse& res);

} // namespace forge
