// SPDX-License-Identifier: MIT OR Apache-2.0
#include "MapsPublisherModule.h"
#include <logos_caller.h>
#include <nlohmann/json.hpp>
extern "C" char* maps_publisher_call(const char*, const char*);
extern "C" void maps_publisher_free(char*);
std::string MapsPublisherModule::owner(const std::string& payload) {
        if (payload.size() > 65536 || payload.find('\0') != std::string::npos)
            return R"({"ok":false,"error":"Publisher request exceeds limit"})";
        // Caller identity is captured from dispatch, never accepted in request JSON.
        const auto caller = logos::currentCaller();
        if (!caller.isModule() || caller.name != "logos_maps" || !caller.instance.empty())
            return R"({"ok":false,"error":"Authenticated Map Library owner required"})";
        const auto context = nlohmann::json({{"kind","module"},{"name",caller.name},{"instance",caller.instance}}).dump();
        char* result = maps_publisher_call(context.c_str(), payload.c_str());
        if (!result) return R"({"ok":false,"error":"Publisher unavailable"})";
        std::string response(result);
        maps_publisher_free(result);
        return response;
    }
