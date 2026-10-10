// SPDX-License-Identifier: MIT OR Apache-2.0
.pragma library

// Consumers supply their ambient Basecamp bridge; no distribution app is needed.
function call(bridge, request, success, failure) {
    function fail(message) { if(failure) failure(message); }
    try {
        bridge.callModuleAsync("prize_maps","request",[JSON.stringify(request)],function(value) {
            var response;
            try {
                response=JSON.parse(value);
                if(typeof response === "string") response=JSON.parse(response);
                if(!response || typeof response !== "object" || typeof response.ok !== "boolean") throw new Error("Invalid response shape");
            } catch(error) { fail("Map SDK returned an unreadable response."); return; }
            if(!response.ok) { fail(typeof response.error === "string" ? response.error : "Map request failed."); return; }
            if(success) success(response.result);
        },60000);
    } catch(error) { fail("The map SDK module is unavailable. Install the prize_maps core module."); }
}
function catalog(bridge, success, failure) {
    call(bridge,{method:"catalog"},success,failure);
}
function query(bridge, rpc, program, page, filter, success, failure) {
    call(bridge,{method:"query",rpc:rpc,program:program,page:page,filter:filter || {kind:"all"}},success,failure);
}
