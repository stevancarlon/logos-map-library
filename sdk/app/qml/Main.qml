// SPDX-License-Identifier: MIT OR Apache-2.0
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

Rectangle {
    id: root
    color: "#f4f4ec"
    implicitWidth: 1180
    implicitHeight: 820
    property alias publisherPanel: publishing
    property alias bulkPanel: bulk
    property alias mapController: control
    property bool narrow: width < 780
    property int section: 0
    property var selected: null
    property var downloadSnapshot: null
    property bool showDetail: false
    property string filter: ""
    property var checkedRegions: []
    function toggleRegion(path, checked) {
        var paths = checkedRegions.filter(function(p) { return p !== path; });
        if (checked) paths.push(path);
        checkedRegions = paths;
    }
    function updateFor(path) {
        return control.updates.find(function(u) { return u.source.region === path; }) || null;
    }
    function versionText(version) {
        var text = String(version);
        return text.slice(0, 4) + "-" + text.slice(4, 6) + "-" + text.slice(6, 8);
    }
    function updateText(update) {
        if (!update) return "";
        if (update.registry_version === null) return "No registered snapshot";
        if (update.update_available) return "New source snapshot available";
        if (update.registry_version > update.source.version) return "Registry claims a newer version";
        return "Versions match · availability unverified";
    }
    readonly property var visibleRegions: control.regions.filter(function (r) {
        return (r.name + " " + r.path).toLowerCase().indexOf(root.filter.toLowerCase()) >= 0;
    })
    readonly property var records: selected && control.queryRegion === selected.path && control.state.kind === "query" ? (control.state.result.records || []) : []
    function hex(bytes) {
        return bytes.map(function (b) {
            return ("0" + b.toString(16)).slice(-2);
        }).join("");
    }
    function chooseRecord(record) {
        cid.text = record.snapshot.cid;
        checksum.text = hex(record.snapshot.checksum);
        limit.text = String(record.snapshot.bytes);
        downloadSnapshot = record.snapshot;
        section = 1;
    }
    MapController {
        id: control
    }
    Connections {
        target: control.bridge
        function onViewModuleReadyChanged(name, ready) {
            if (name === "logos_maps" && ready)
                control.attach();
        }
    }
    FileDialog {
        id: openFile
        title: "Choose a local map file"
        onAccepted: localFile.text = selectedFile.toString()
    }
    FileDialog {
        id: saveFile
        title: "Save downloaded map"
        fileMode: FileDialog.SaveFile
        defaultSuffix: "osm.pbf"
        onAccepted: localFile.text = selectedFile.toString()
    }
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: root.narrow ? 18 : 30
        spacing: 18
        RowLayout {
            Layout.fillWidth: true
            ColumnLayout {
                spacing: 4
                Text {
                    textFormat: Text.PlainText

                    text: "MAP SNAPSHOTS"
                    font.pixelSize: 11
                    font.letterSpacing: 2
                    color: "#5a725b"
                    font.weight: Font.DemiBold
                }
                Text {
                    textFormat: Text.PlainText

                    text: "Map Library"
                    font.family: "Noto Serif"
                    font.pixelSize: root.narrow ? 24 : 30
                    color: "#183d28"
                }
            }
            Item {
                Layout.fillWidth: true
            }
            Text {
                textFormat: Text.PlainText

                visible: !root.narrow
                text: "Local development build"
                font.pixelSize: 12
                color: "#6a7468"
            }
        }
        GridLayout {
            Layout.fillWidth: true
            columns: root.narrow ? 3 : 7
            columnSpacing: 8
            rowSpacing: 8
            Repeater {
                model: ["Library", "File operations", "Connections", "Publishing", "Bulk hosting"]
                delegate: ActionButton {
                    required property string modelData
                    required property int index
                    Layout.fillWidth: root.narrow
                    text: modelData
                    primary: root.section === index
                    onClicked: root.section = index
                }
            }
            Item {
                visible: !root.narrow
                Layout.fillWidth: true
            }
            Text {
                textFormat: Text.PlainText

                visible: !root.narrow
                text: control.ready ? "72 supported regions" : "Connecting to app backend…"
                color: "#65705f"
                font.pixelSize: 12
            }
        }
        Rectangle {
            visible: control.error !== "" || control.state.error !== ""
            Layout.fillWidth: true
            implicitHeight: errorText.implicitHeight + 24
            color: "#f6e9dc"
            radius: 8
            Text {
                id: errorText
                textFormat: Text.PlainText
                anchors.fill: parent
                anchors.margins: 12
                text: control.error || control.state.error
                color: "#7a3f23"
                font.pixelSize: 13
                wrapMode: Text.Wrap
            }
        }
        RowLayout {
            visible: control.state.running
            Layout.fillWidth: true
            BusyIndicator {
                running: control.state.running
                implicitWidth: 30
                implicitHeight: 30
            }
            Text {
                textFormat: Text.PlainText

                text: "Working on " + control.state.kind + "…"
                color: "#3b513e"
                Layout.fillWidth: true
            }
            ActionButton {
                text: "Cancel"
                onClicked: control.start({
                    op: "cancel"
                })
            }
        }
        StackLayout {
            currentIndex: root.section
            Layout.fillWidth: true
            Layout.fillHeight: true
            RowLayout {
                spacing: 24
                ColumnLayout {
                    visible: !root.narrow || !root.showDetail
                    Layout.preferredWidth: 320
                    Layout.fillWidth: root.narrow
                    Layout.fillHeight: true
                    spacing: 12
                    TextField {
                        Layout.fillWidth: true
                        implicitHeight: 44
                        placeholderText: "Find a country or region"
                        onTextChanged: root.filter = text
                        selectByMouse: true
                    }
                    Text {
                        textFormat: Text.PlainText

                        text: root.visibleRegions.length + " regions · fixed, non-overlapping catalog"
                        color: "#737d6d"
                        font.pixelSize: 11
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                    }
                    ActionButton {
                        Layout.fillWidth: true
                        text: "Refresh source catalog"
                        enabled: control.ready && !control.state.running
                        onClicked: control.refreshCatalog()
                    }
                    Text {
                        Layout.fillWidth:true;wrapMode:Text.Wrap;textFormat:Text.PlainText
                        color:"#63715d";font.pixelSize:11
                        text:control.sourceCatalog.checked_at ?
                            "Source index checked "+control.sourceCatalog.checked_at+" · "+control.sourceCatalog.catalog.regions.length+" available. Saved source dates may change." :
                            "Bundled region list. Refresh contacts Geofabrik for availability and source dates."
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        ActionButton {
                            text: "Select visible"
                            enabled: !control.state.running
                            onClicked: {
                                var paths = root.checkedRegions.slice();
                                root.visibleRegions.forEach(function(r) { if (paths.indexOf(r.path) < 0) paths.push(r.path); });
                                root.checkedRegions = paths;
                            }
                        }
                        ActionButton {
                            text: "Clear"
                            enabled: !control.state.running && root.checkedRegions.length > 0
                            onClicked: root.checkedRegions = []
                        }
                    }
                    ActionButton {
                        Layout.fillWidth: true
                        text: "Check updates (" + root.checkedRegions.length + ")"
                        enabled: !control.state.running && root.checkedRegions.length > 0
                        onClicked: control.checkUpdates(root.checkedRegions)
                    }
                    ActionButton {
                        Layout.fillWidth: true
                        text: "Host selected regions"
                        enabled: !control.state.running && root.checkedRegions.length > 0
                        onClicked: root.section = 4
                    }
                    Text {
                        Layout.fillWidth: true
                        text: "Update checks contact Geofabrik and your registry."
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                        font.pixelSize: 11
                        color: "#63715d"
                    }
                    ListView {
                        id: list
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 4
                        model: root.visibleRegions
                        ScrollBar.vertical: ScrollBar {}
                        delegate: ItemDelegate {
                            id: regionRow
                            required property var modelData
                            width: list.width
                            height: 94
                            leftPadding: 48
                            CheckBox {
                                anchors.left: parent.left
                                anchors.verticalCenter: parent.verticalCenter
                                width: 44
                                height: 44
                                checked: root.checkedRegions.indexOf(regionRow.modelData.path) >= 0
                                enabled: !control.state.running
                                Accessible.name: "Select " + regionRow.modelData.name
                                onToggled: root.toggleRegion(regionRow.modelData.path, checked)
                            }
                            onClicked: {
                                root.selected = modelData;
                                root.showDetail = true;
                            }
                            background: Rectangle {
                                radius: 8
                                color: root.selected && root.selected.path === parent.modelData.path ? "#dde6d5" : parent.hovered ? "#e9ede1" : "transparent"
                            }
                            contentItem: Column {
                                spacing: 4
                                Text {
                                    textFormat: Text.PlainText

                                    width: parent.width
                                    text: parent.parent.modelData.name
                                    color: "#25412b"
                                    font.pixelSize: 14
                                    font.weight: Font.Medium
                                    elide: Text.ElideRight
                                }
                                Text {
                                    textFormat: Text.PlainText

                                    width: parent.width
                                    text: parent.parent.modelData.path
                                    color: "#707b67"
                                    font.pixelSize: 11
                                    elide: Text.ElideMiddle
                                }
                                Text {
                                    width:parent.width;elide:Text.ElideRight;textFormat:Text.PlainText
                                    color:"#63715d";font.pixelSize:11
                                    text:regionRow.modelData.level+" · "+(control.sourceInfo(regionRow.modelData.path) ?
                                        (control.sourceInfo(regionRow.modelData.path).source ? root.versionText(control.sourceInfo(regionRow.modelData.path).source.version) : "source date unavailable") :
                                        (control.sourceCatalog.checked_at ? "not in source index" : "source date not checked"))
                                }
                                Text {
                                    width: parent.width
                                    visible: !!root.updateFor(regionRow.modelData.path)
                                    text: root.updateText(root.updateFor(regionRow.modelData.path))
                                    textFormat: Text.PlainText
                                    elide: Text.ElideRight
                                    color: "#385436"
                                    font.pixelSize: 11
                                }
                            }
                        }
                    }
                }
                Rectangle {
                    visible: !root.narrow || root.showDetail
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    color: "#ffffff"
                    radius: 12
                    ScrollView {
                        anchors.fill: parent
                        anchors.margins: root.narrow ? 16 : 24
                        clip: true
                        contentWidth: availableWidth
                        ColumnLayout {
                            width: parent.width
                            spacing: 18
                            ActionButton {
                                visible: root.narrow
                                text: "‹ All regions"
                                onClicked: root.showDetail = false
                            }
                            Text {
                                textFormat: Text.PlainText

                                Layout.fillWidth: true
                                text: root.selected ? root.selected.name : "Choose a region"
                                font.family: "Noto Serif"
                                font.pixelSize: 27
                                color: "#1d4229"
                                wrapMode: Text.Wrap
                            }
                            Text {
                                textFormat: Text.PlainText

                                Layout.fillWidth: true
                                text: root.selected ? root.selected.path : "Browse the supported catalog, then look up hosted snapshots on your configured LEZ node."
                                color: "#6c7868"
                                font.pixelSize: 13
                                wrapMode: Text.WrapAnywhere
                            }
                            Text {
                                textFormat: Text.PlainText

                                visible: !!root.selected
                                Layout.fillWidth: true
                                text: root.selected ? (root.selected.level === "country" ? "Country extract" : "Subregion of " + root.selected.parent) : ""
                                color: "#4e684d"
                                font.pixelSize: 12
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                visible: !!root.selected && !!root.updateFor(root.selected.path)
                                property var update: root.selected ? root.updateFor(root.selected.path) : null
                                Text {
                                    Layout.fillWidth: true
                                    text: root.updateText(parent.update)
                                    textFormat: Text.PlainText
                                    wrapMode: Text.Wrap
                                    color: "#25412b"
                                    font.weight: Font.DemiBold
                                    font.pixelSize: 14
                                }
                                Text {
                                    Layout.fillWidth: true
                                    text: parent.update ? "Geofabrik: " + root.versionText(parent.update.source.version)
                                        + " · Registry: " + (parent.update.registry_version === null ? "none" : root.versionText(parent.update.registry_version))
                                        + "\nChecked at " + control.updatesCheckedAt + ". Registry versions are unverified hosting claims." : ""
                                    textFormat: Text.PlainText
                                    wrapMode: Text.Wrap
                                    color: "#63715d"
                                    font.pixelSize: 12
                                }
                            }
                            ActionButton {
                                visible: !!root.selected
                                text: "Find hosted snapshots"
                                primary: true
                                enabled: !control.state.running
                                onClicked: control.query(root.selected.path, 0)
                            }
                            ActionButton {
                                visible: !!root.selected
                                text: "Import from Geofabrik…"
                                enabled: !control.state.running
                                onClicked: root.section = 1
                            }
                            Rectangle {
                                Layout.fillWidth: true
                                implicitHeight: trust.implicitHeight + 24
                                color: "#f1f4eb"
                                radius: 8
                                Text {
                                    id: trust
                                    textFormat: Text.PlainText
                                    anchors.fill: parent
                                    anchors.margins: 12
                                    text: "Registry entries are hosting claims. Inspect the source, checksum and registrant before choosing a file. Registry lookups and hosted downloads do not contact Geofabrik."
                                    color: "#52624b"
                                    font.pixelSize: 12
                                    wrapMode: Text.Wrap
                                }
                            }
                            Text {
                                textFormat: Text.PlainText

                                visible: root.records.length === 0
                                Layout.fillWidth: true
                                text: root.selected && control.queryRegion === root.selected.path && control.state.kind === "query" && !control.state.running && !control.state.error ? "No announcements on this page." : "Hosting availability has not been checked."
                                color: "#7b8375"
                                font.pixelSize: 13
                                wrapMode: Text.Wrap
                            }
                            Repeater {
                                model: root.records
                                delegate: Rectangle {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    implicitHeight: recordColumn.implicitHeight + 28
                                    color: "#f7f8f3"
                                    radius: 10
                                    ColumnLayout {
                                        id: recordColumn
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.top: parent.top
                                        anchors.margins: 14
                                        spacing: 10
                                        Text {
                                            textFormat: Text.PlainText

                                            text: "Snapshot " + parent.parent.modelData.snapshot.version + " · unverified claim"
                                            color: "#385436"
                                            font.pixelSize: 13
                                            Layout.fillWidth: true
                                            wrapMode: Text.Wrap
                                        }
                                        Text {
                                            textFormat: Text.PlainText

                                            text: parent.parent.modelData.snapshot.cid
                                            color: "#677562"
                                            font.family: "monospace"
                                            font.pixelSize: 11
                                            Layout.fillWidth: true
                                            wrapMode: Text.WrapAnywhere
                                        }
                                        Text {
                                            textFormat: Text.PlainText

                                            text: parent.parent.modelData.snapshot.bytes.toLocaleString() + " bytes"
                                            color: "#64715f"
                                            font.pixelSize: 12
                                        }
                                        Text {
                                            textFormat: Text.PlainText
                                            Layout.fillWidth: true
                                            text: "MD5  " + root.hex(parent.parent.modelData.snapshot.checksum)
                                            font.family: "monospace"
                                            font.pixelSize: 11
                                            color: "#64715f"
                                            wrapMode: Text.WrapAnywhere
                                        }
                                        Text {
                                            textFormat: Text.PlainText
                                            Layout.fillWidth: true
                                            text: "Registrant  " + root.hex(parent.parent.modelData.registrant)
                                            font.family: "monospace"
                                            font.pixelSize: 11
                                            color: "#64715f"
                                            wrapMode: Text.WrapAnywhere
                                        }
                                        ActionButton {
                                            text: "Use for download"
                                            onClicked: root.chooseRecord(parent.parent.modelData)
                                        }
                                    }
                                }
                            }
                            ActionButton {
                                visible: root.selected && control.queryRegion === root.selected.path && control.state.result.next_page !== undefined && control.state.result.next_page !== null
                                text: "Next registry page"
                                enabled: !control.state.running
                                onClicked: control.query(root.selected.path, control.state.result.next_page)
                            }
                            Item {
                                Layout.preferredHeight: 20
                            }
                        }
                    }
                }
            }
            ScrollView {
                contentWidth: availableWidth
                clip: true
                ColumnLayout {
                    width: parent.width
                    spacing: 16
                    Text {
                        textFormat: Text.PlainText

                        text: "Import and share maps"
                        font.family: "Noto Serif"
                        font.pixelSize: 26
                        color: "#23482d"
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                    }
                    Text {
                        textFormat: Text.PlainText

                        text: "Import contacts Geofabrik and checks its published checksum. Storage downloads use only your configured node. Uploads are public. Verify and store creates a snapshot for review in Publishing; registration requires a separate approval."
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        color: "#63715d"
                        font.pixelSize: 13
                    }
                    Label {
                        text: "Local file / download destination"
                        color: "#395333"
                    }
                    TextField {
                        id: localFile
                        Layout.fillWidth: true
                        implicitHeight: 44
                        placeholderText: "Absolute path to a PBF file"
                        selectByMouse: true
                    }
                    RowLayout {
                        ActionButton {
                            text: "Open file…"
                            onClicked: openFile.open()
                        }
                        ActionButton {
                            text: "Choose destination…"
                            onClicked: saveFile.open()
                        }
                    }
                    Label {
                        text: "Expected MD5 · fetched automatically for imports"
                        color: "#395333"
                    }
                    TextField {
                        onTextEdited: root.downloadSnapshot = null
                        id: checksum
                        Layout.fillWidth: true
                        implicitHeight: 44
                        placeholderText: "32 hexadecimal characters"
                        maximumLength: 32
                        selectByMouse: true
                        font.family: "monospace"
                    }
                    Label {
                        text: "Maximum file size in bytes"
                        color: "#395333"
                    }
                    TextField {
                        id: limit
                        Layout.fillWidth: true
                        implicitHeight: 44
                        text: "2147483648"
                        selectByMouse: true
                        validator: RegularExpressionValidator {
                            regularExpression: /[0-9]{1,12}/
                        }
                    }
                    Label {text:"Source snapshot date · YYYYMMDD (blank uses latest)";color:"#395333"}
                    TextField {id:hostVersion;Layout.fillWidth:true;implicitHeight:44;placeholderText:"For an older local extract, enter its published date";maximumLength:8;selectByMouse:true}
                    Label {
                        text: "Storage CID · needed for download"
                        color: "#395333"
                    }
                    TextField {
                        onTextEdited: root.downloadSnapshot = null
                        id: cid
                        Layout.fillWidth: true
                        implicitHeight: 44
                        placeholderText: "Content identifier"
                        selectByMouse: true
                        maximumLength: 128
                    }
                    Flow {
                        Layout.fillWidth: true
                        spacing: 8
                        ActionButton {
                            text: "Verify and store local region"
                            primary: true
                            enabled: !control.state.running && root.selected !== null
                            onClicked: control.start({op:"host_local",region:root.selected.path,file:localFile.text,limit:limit.text,version:hostVersion.text})
                        }
                        ActionButton {
                            text: "Fetch and store region"
                            enabled: !control.state.running && root.selected !== null
                            onClicked: control.start({op:"host_fetch",region:root.selected.path,file:localFile.text,limit:limit.text,version:hostVersion.text})
                        }
                        ActionButton {
                            text: "Import from Geofabrik"
                            enabled: !control.state.running && root.selected !== null
                            onClicked: control.start({
                                op: "fetch",
                                region: root.selected.path,
                                file: localFile.text,
                                limit: limit.text
                            })
                        }
                        ActionButton {
                            text: "Verify local file"
                            enabled: !control.state.running
                            onClicked: control.start({
                                op: "verify",
                                file: localFile.text,
                                md5: checksum.text,
                                limit: limit.text
                            })
                        }
                        ActionButton {
                            text: "Upload to Storage"
                            primary: true
                            enabled: !control.state.running
                            onClicked: control.start({
                                op: "upload",
                                file: localFile.text,
                                md5: checksum.text,
                                limit: limit.text
                            })
                        }
                        ActionButton {
                            text: root.downloadSnapshot ? "Download selected snapshot" : "Download by CID"
                            enabled: !control.state.running
                            onClicked: control.start({
                                op: root.downloadSnapshot ? "download_snapshot" : "download",
                                snapshot: root.downloadSnapshot,
                                file: localFile.text,
                                md5: checksum.text,
                                limit: limit.text,
                                cid: cid.text
                            })
                        }
                    }
                    Text {
                        textFormat: Text.PlainText
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        text: root.downloadSnapshot ? "Selected registry snapshot: SHA-256, MD5 and exact file size will be checked. Editing CID or MD5 switches to manual verification." : root.selected ? "Import region: " + root.selected.name + " · " + root.selected.path : "Select a region in Library to import its latest extract."
                        color: "#63715d"
                        font.pixelSize: 13
                    }
                    Rectangle {
                        visible: !control.state.running && control.state.kind !== "query" && Object.keys(control.state.result).length > 0
                        Layout.fillWidth: true
                        implicitHeight: resultColumn.implicitHeight + 28
                        color: "#e6eddf"
                        radius: 10
                        ColumnLayout {
                            id: resultColumn
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.margins: 14
                            spacing: 10
                            Text {
                                textFormat: Text.PlainText

                                text: control.state.kind === "upload" ? "Uploaded · not registered" : control.state.kind === "fetch" ? "Imported · not uploaded or registered" : "Checksum verified"
                                color: "#27482c"
                                font.weight: Font.DemiBold
                            }
                            Text {
                                textFormat: Text.PlainText

                                Layout.fillWidth: true
                                text: (control.state.result.cid ? "CID  " + control.state.result.cid + "\n\n" : "") + "Bytes  " + (control.state.result.content || control.state.result).bytes + "\nMD5  " + (control.state.result.content || control.state.result).md5 + "\nSHA-256  " + (control.state.result.content || control.state.result).sha256
                                font.family: "monospace"
                                font.pixelSize: 11
                                color: "#53624b"
                                wrapMode: Text.WrapAnywhere
                            }
                            ActionButton {
                                visible: control.state.kind === "fetch"
                                text: "Use checksum for upload"
                                onClicked: checksum.text = control.state.result.content.md5
                            }
                        }
                    }
                    Item {
                        Layout.preferredHeight: 24
                    }
                }
            }
            ScrollView {
                contentWidth: availableWidth
                clip: true
                ColumnLayout {
                    width: parent.width
                    spacing: 16
                    Text {
                        textFormat: Text.PlainText

                        text: "Your connections"
                        font.family: "Noto Serif"
                        font.pixelSize: 26
                        color: "#23482d"
                    }
                    Text {
                        textFormat: Text.PlainText

                        Layout.fillWidth: true
                        text: "Choose the nodes you use. No public endpoint or third-party indexer is selected for you. Saving settings does not establish a connection."
                        color: "#63715d"
                        font.pixelSize: 13
                        wrapMode: Text.Wrap
                    }
                    Label {
                        text: "LEZ sequencer RPC"
                        color: "#395333"
                    }
                    TextField {
                        id: rpc
                        Layout.fillWidth: true
                        implicitHeight: 44
                        text: control.state.rpc
                        selectByMouse: true
                    }
                    Label {
                        text: "Deployed v0.3 map registry account address"
                        color: "#395333"
                    }
                    TextField {
                        id: program
                        Layout.fillWidth: true
                        implicitHeight: 44
                        text: control.state.program
                        placeholderText: "Registry account address from your deployment"
                        maximumLength: 44
                        selectByMouse: true
                        font.family: "monospace"
                    }
                    Label {
                        text: "Logos Storage API"
                        color: "#395333"
                    }
                    TextField {
                        id: storage
                        Layout.fillWidth: true
                        implicitHeight: 44
                        text: control.state.storage
                        selectByMouse: true
                    }
                    ActionButton {
                        text: "Save connections"
                        primary: true
                        enabled: !control.state.running && !publishing.busy
                        onClicked: control.settings(rpc.text, program.text, storage.text)
                    }
                    Text {
                        textFormat: Text.PlainText

                        text: "This build has not been validated on testnet 0.3. Native wallet and NFT interfaces are not included here."
                        Layout.fillWidth: true
                        color: "#7c7862"
                        font.pixelSize: 12
                        wrapMode: Text.Wrap
                    }
                    Item {
                        Layout.preferredHeight: 24
                    }
                }
            }
            PublisherPanel {
                id: publishing
                rpc: control.state.rpc
                program: control.state.program
                snapshots: control.state.stored_snapshots || []
            }
            BulkPanel {
                id: bulk
                control: root.mapController
                paths: root.checkedRegions
            }
        }
    }
}
