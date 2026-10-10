// SPDX-License-Identifier: MIT OR Apache-2.0
import QtQuick

QtObject {
    id: ctl
    property var backend: typeof mapsLocal !== "undefined" ? mapsLocal : null
    property var bridge: typeof logos !== "undefined" ? logos : null
    property var regions: []
    property var state: ({
            running: false,
            result: {},
            error: "",
            rpc: "http://127.0.0.1:3040",
            storage: "http://127.0.0.1:8080/api/storage/v1",
            program: ""
        })
    property string error: ""
    property string queryRegion: ""
    property bool polling: false
    property bool ready: false
    property bool attached: false
    property var updates: []
    property string updatesCheckedAt: ""
    readonly property var sourceCatalog: state.source_catalog || ({})
    function sourceInfo(path) {
        return (sourceCatalog.versions || []).find(function(row) {return row.region===path;}) || null;
    }
    function refreshCatalog() {start({op:"discover"});}
    property Timer timer: Timer {
        interval: 250
        repeat: true
        running: ctl.state.running
        onTriggered: ctl.poll()
    }
    function call(command, callback) {
        if (!backend) {
            error = "Map backend is not ready.";
            return;
        }
        function done(raw) {
            try {
                var r = JSON.parse(raw);
                if (!r.ok)
                    throw Error(r.error);
                if (callback)
                    callback(r);
            } catch (e) {
                ctl.error = String(e);
                ctl.polling = false;
            }
        }
        try {
            if (typeof mapsLocal !== "undefined")
                done(backend.dispatch(JSON.stringify(command)));
            else
                bridge.watch(backend.dispatch(JSON.stringify(command)), done, function (e) {
                    ctl.error = String(e);
                    ctl.polling = false;
                });
        } catch (e) {
            error = String(e);
            polling = false;
        }
    }
    function attach() {
        if (attached) return;
        if (!backend && bridge)
            backend = bridge.module("logos_maps");
        if (backend) {
            attached = true;
            if (typeof mapsLocal !== "undefined") {
                call({op: "catalog"}, function(r) { state = r; });
            } else {
                bridge.callModuleAsync("maps_distribution", "request",
                    [JSON.stringify({method: "catalog"})], function(raw) {
                        try {
                            var response = JSON.parse(raw);
                            if (typeof response === "string") response = JSON.parse(response);
                            if (!response.ok) throw Error(response.error || "Distribution catalog unavailable");
                            var catalog = response.result.canonical_regions;
                            if (!Array.isArray(catalog) || catalog.length !== 72)
                                throw Error("Invalid distribution catalog");
                            ctl.acceptCatalog(catalog);
                        } catch (e) { ctl.error = String(e); }
                    }, 60000);
            }
            poll();
        }
    }
    function acceptCatalog(catalog) {
        regions = catalog;
        ready = true;
        console.log("MAP_LIBRARY_READY", regions.length);
    }
    function poll() {
        if (polling)
            return;
        polling = true;
        call({
            op: "state"
        }, function (r) {
            state = r;
            polling = false;
            if (!r.running && r.kind === "updates" && !r.error && r.result.updates) {
                updates = r.result.updates;
                updatesCheckedAt = new Date().toLocaleTimeString();
            }
            if (!ready && !r.running && r.kind === "catalog" && !r.error && r.result.canonical_regions) {
                acceptCatalog(r.result.canonical_regions);
            }
        });
    }
    function start(command) {
        error = "";
        call(command, function (r) {
            state = r;
        });
    }
    function query(region, page) {
        queryRegion = region;
        start({
            op: "query",
            region: region,
            page: page
        });
    }
    function settings(rpc, program, storage) {
        updates = [];
        updatesCheckedAt = "";
        start({
            op: "settings",
            rpc: rpc,
            program: program,
            storage: storage
        });
    }
    function checkUpdates(paths) {
        updates = [];
        updatesCheckedAt = "";
        start({op: "updates", regions: paths, max_pages: 4096});
    }
    Component.onCompleted: attach()
}
