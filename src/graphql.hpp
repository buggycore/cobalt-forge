#pragma once

#include "http_types.hpp"
#include "store.hpp"

namespace forge {

// Handles POST /api/graphql. Returns true if path matched.
bool handle_graphql(ForgeStore& store, const HttpRequest& req, HttpResponse& res);

} // namespace forge
