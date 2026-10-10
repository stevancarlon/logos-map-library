// SPDX-License-Identifier: MIT OR Apache-2.0
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "MapRegistry.js" as Maps

Rectangle {
    id: root
    color: "#f5f5ed"; implicitWidth: 960; implicitHeight: 740
    property bool busy: false
    property bool catalogLoaded: false
    property bool queried: false
    property string registryProtocol: "legacy"
    property bool isV03: registryProtocol === "lez-v0.3"
    property bool validProgram: isV03 ? /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(program.trim()) : /^[a-fA-F0-9]{64}$/.test(program.trim())
    property string error: ""
    property var regions: []
    property var records: []
    property var nextPage: null
    property alias rpc: rpcInput.text
    property alias program: programInput.text
    property alias region: regionInput.text
    function fail(message) { busy=false; error=message; }
    function loadCatalog() {
        busy=true; error="";
        Maps.catalog(logos,function(value) { root.regions=value.canonical_regions; root.registryProtocol=value.registry_protocol || "legacy"; root.catalogLoaded=true; root.busy=false; },fail);
    }
    function search(page, replace) {
        if(busy) return;
        busy=true; error="";
        Maps.query(logos,rpc.trim(),program.trim(),page,region.trim() ? {kind:"region",value:region.trim()} : {kind:"all"},function(value) {
            root.records=replace ? value.records : root.records.concat(value.records);
            root.nextPage=value.next_page; root.queried=true; root.busy=false;
        },fail);
    }
    function resetResults() { records=[]; nextPage=null; queried=false; }
    Component.onCompleted: loadCatalog()
    component Body: Label { textFormat:Text.PlainText; wrapMode:Text.Wrap; Layout.fillWidth:true; color:"#526055"; font.pixelSize:14 }
    component Action: Button { implicitHeight:44; font.pixelSize:14 }
    ColumnLayout {
        anchors.fill:parent; anchors.margins:24; spacing:14
        Label { text:"Map SDK Explorer"; textFormat:Text.PlainText; color:"#234330"; font.pixelSize:26; font.bold:true }
        Body { text:"Discover map snapshots through the standalone SDK. The distribution app is not required." }
        RowLayout {
            Layout.fillWidth:true
            Body { text:catalogLoaded ? regions.length+" supported regions · bundled catalog" : "Catalog not loaded" }
            Action { text:"Reload catalog"; enabled:!root.busy; onClicked:root.loadCatalog() }
        }
        Frame {
            Layout.fillWidth:true; padding:16
            background:Rectangle { color:"white"; radius:8; border.color:"#dce4d7" }
            ColumnLayout {
                anchors.fill:parent; spacing:8
                Body { text:"Sequencer RPC" }
                TextField { id:rpcInput; Layout.fillWidth:true; implicitHeight:44; placeholderText:"https://your-sequencer"; enabled:!root.busy; onTextChanged:root.resetResults() }
                Body { text:root.isV03 ? "Deployed map registry account address" : "Deployed map registry image ID" }
                TextField { id:programInput; Layout.fillWidth:true; implicitHeight:44; placeholderText:root.isV03 ? "Registry account address from your deployment" : "64 hexadecimal characters"; enabled:!root.busy; onTextChanged:root.resetResults() }
                Body { text:"Region path · leave empty for all regions" }
                TextField { id:regionInput; Layout.fillWidth:true; implicitHeight:44; placeholderText:"africa/ethiopia"; enabled:!root.busy; onTextChanged:root.resetResults() }
                Action { text:root.busy ? "Loading…" : "Find snapshots"; enabled:!root.busy && root.rpc.trim().length>0 && root.validProgram; onClicked:root.search(0,true) }
            }
        }
        Body { visible:root.error.length>0; text:root.error; color:"#963f32" }
        Body { text:root.queried ? root.records.length+" announcements loaded. Verify downloaded bytes before using these files." : "Queries read public registry announcements. They do not download files or verify hosting availability." }
        Body { visible:root.queried && !root.records.length; text:root.nextPage===null ? "No matching snapshots were found." : "No matches on this page. Continue to the next page." }
        ScrollView {
            Layout.fillWidth:true; Layout.fillHeight:true; clip:true; contentWidth:availableWidth
            ColumnLayout {
                width:parent.width; spacing:10
                Repeater { model:root.records
                    Frame {
                        required property var modelData; Layout.fillWidth:true; padding:14
                        background:Rectangle { color:"white"; radius:8; border.color:"#dce4d7" }
                        ColumnLayout {
                            anchors.fill:parent
                            Body { text:modelData.snapshot.region+" · version "+modelData.snapshot.version; color:"#234330"; font.bold:true }
                            Body { text:"Unverified hosting announcement · "+modelData.snapshot.bytes+" bytes" }
                            TextEdit { text:modelData.snapshot.cid; textFormat:TextEdit.PlainText; readOnly:true; selectByMouse:true; wrapMode:TextEdit.Wrap; Layout.fillWidth:true; color:"#234330"; font.pixelSize:13 }
                        }
                    }
                }
            }
        }
        Action { text:"Load next page"; visible:root.nextPage!==null; enabled:!root.busy; onClicked:root.search(root.nextPage,false) }
    }
}
