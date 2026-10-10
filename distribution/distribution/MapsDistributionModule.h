// SPDX-License-Identifier: MIT OR Apache-2.0
#pragma once
#include <string>
class MapsDistributionModule {
public:
    /// Reads only public registry data or the bundled region catalog.
    std::string request(const std::string& payload);
};
