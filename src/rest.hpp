#pragma once

#include "http_types.hpp"
#include "store.hpp"

namespace forge {

// Handles all /api/v3* routes. Returns true if matched.
bool handle_rest(ForgeStore& store, const HttpRequest& req, HttpResponse& res);

} // namespace forge
