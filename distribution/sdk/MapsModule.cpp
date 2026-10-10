// SPDX-License-Identifier: MIT OR Apache-2.0
#include "MapsModule.h"
extern "C" char* prize_maps_request(const char*);
extern "C" void prize_maps_free(char*);
std::string MapsModule::request(const std::string& payload) {
        if (payload.size() > 8192U || payload.find('\0') != std::string::npos)
            return R"({"ok":false,"error":"Map request exceeds limits"})";
        char* result = prize_maps_request(payload.c_str());
        if (!result) return R"({"ok":false,"error":"Map SDK unavailable"})";
        std::string response(result);
        prize_maps_free(result);
        return response;
    }
