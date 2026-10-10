// SPDX-License-Identifier: MIT OR Apache-2.0
import QtQuick
QtObject {
    id: ctl
    property var bridge: typeof logos !== "undefined" ? logos : null
    property bool busy: false
    property bool unlocked: false
    property string author: ""
    property string error: ""
    property var review: null
    property var history: []
    property var lastSubmission: null
    property string completion: ""
    property Timer statusTimer: Timer {
        interval: 30000; repeat: true; running: ctl.unlocked && !ctl.busy
        onTriggered: ctl.call({op:"status"}, function(r) {
            ctl.unlocked=r.unlocked;
            if (!r.unlocked) {ctl.author="";ctl.review=null;}
        })
    }
    function call(request, success) {
        if (busy) return;
        if (!bridge) {error="Publishing requires the Map Library running inside Basecamp.";return;}
        busy=true;error="";
        try {
            bridge.callModuleAsync("maps_publisher","owner",[JSON.stringify(request)],function(raw) {
                busy=false;
                try {
                    var r=JSON.parse(raw);
                    if(typeof r==="string")r=JSON.parse(r);
                    if(!r.ok)throw Error(r.error || "Publisher request failed");
                    if(success)success(r.result);
                } catch(e) {error=String(e);}
            },180000);
        } catch(e) {busy=false;error="The native map publisher is unavailable. Build and install the publisher module.";}
    }
    function unlock(rpc,program,keyPath,outboxPath,keyPassword,outboxPassword) {
        review=null;author="";unlocked=false;history=[];lastSubmission=null;completion="";
        call({op:"unlock",rpc:rpc,program:program,key_path:keyPath,outbox_path:outboxPath,
            key_password:keyPassword,outbox_password:outboxPassword},function(r) {unlocked=r.unlocked;author=r.author;refresh();});
    }
    function lock() {
        if(busy)return;
        review=null;author="";unlocked=false;history=[];lastSubmission=null;completion="";
        call({op:"lock"});
    }
    function prepare(snapshots,gas,cap,tip) {
        review=null;completion="";
        call({op:"next_registration",snapshots:snapshots,gas_limit:gas,max_fee:cap,tip:tip},function(r) {
            if(r.complete) completion="All selected snapshots have matching registry records by this account.";
            else review=r;
        });
    }
    function cancel() {review=null;call({op:"cancel"});}
    function approve() {
        if(!review)return;
        var digest=review.digest;review=null;
        call({op:"approve",digest:digest},function(r) {lastSubmission=r;refresh();});
    }
    function refresh() {call({op:"history"},function(r) {history=r;});}
    function reconcile(hash) {call({op:"reconcile",hash:hash},function(r) {lastSubmission=r;refresh();});}
}
