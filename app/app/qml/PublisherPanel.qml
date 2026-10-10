// SPDX-License-Identifier: MIT OR Apache-2.0
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
ScrollView {
    id: panel
    required property string rpc
    required property string program
    property var snapshots: []
    property var selectedCids: []
    property alias controller: publisher
    property alias keyPath: keyPathInput.text
    property alias outboxPath: outboxPathInput.text
    property alias keyPassword: keyPasswordInput.text
    property alias outboxPassword: outboxPasswordInput.text
    readonly property bool busy: publisher.busy
    readonly property var selectedSnapshots: snapshots.filter(function(s) {return selectedCids.indexOf(s.region+"|"+s.cid+"|"+s.version)>=0;})
    contentWidth: availableWidth
    clip: true
    function unlock() {
        publisher.unlock(rpc,program,keyPathInput.text.trim(),outboxPathInput.text.trim(),keyPasswordInput.text,outboxPasswordInput.text);
        keyPasswordInput.clear();outboxPasswordInput.clear();
    }
    function chooseAll() {selectedCids=snapshots.map(function(s) {return s.region+"|"+s.cid+"|"+s.version;});}
    function prepare() {publisher.prepare(selectedSnapshots,gas.text,cap.text,tip.text);}
    function connectionChanged() {if(publisher && publisher.unlocked&&!publisher.busy)publisher.lock();}
    onSelectedSnapshotsChanged: {if(publisher) publisher.completion = "";}
    onRpcChanged: connectionChanged()
    onProgramChanged: connectionChanged()
    PublisherController {id: publisher}
    FileDialog {
        id: picker
        property bool choosingKey: true
        title: choosingKey ? "Choose encrypted signing key" : "Choose publisher outbox"
        onAccepted: {
            var path=decodeURIComponent(selectedFile.toString().replace(/^file:\/\//,""));
            if(choosingKey)keyPathInput.text=path;else outboxPathInput.text=path;
        }
    }
    ColumnLayout {
        width: panel.availableWidth
        spacing: 14
        Text {text:"Publish stored snapshots";font.family:"Noto Serif";font.pixelSize:26;color:"#23482d";textFormat:Text.PlainText;Layout.fillWidth:true;wrapMode:Text.Wrap}
        Text {text:"Verify and store a region in File operations, then select its snapshot here. Registration publishes its metadata to your configured registry.";color:"#63715d";font.pixelSize:13;Layout.fillWidth:true;wrapMode:Text.Wrap;textFormat:Text.PlainText}
        Text {visible:publisher.error.length>0;text:publisher.error;color:"#8b4327";Layout.fillWidth:true;wrapMode:Text.Wrap;textFormat:Text.PlainText}
        Text {visible:publisher.completion.length>0;text:publisher.completion;Layout.fillWidth:true;wrapMode:Text.Wrap;color:"#395333";textFormat:Text.PlainText}
        RowLayout {
            visible:publisher.busy
            BusyIndicator {running:publisher.busy;implicitWidth:28;implicitHeight:28}
            Text {text:"Waiting for the publisher…";color:"#395333";textFormat:Text.PlainText}
        }
        ColumnLayout {
            visible:!publisher.unlocked
            Layout.fillWidth:true
            Label {text:"Encrypted signing key"}
            RowLayout {
                Layout.fillWidth:true
                TextField {id:keyPathInput;Layout.fillWidth:true;implicitHeight:44;placeholderText:"Absolute path to the key vault";selectByMouse:true;enabled:!publisher.busy}
                ActionButton {text:"Browse";enabled:!publisher.busy;onClicked:{picker.choosingKey=true;picker.open();}}
            }
            Label {text:"Encrypted publisher outbox"}
            RowLayout {
                Layout.fillWidth:true
                TextField {id:outboxPathInput;Layout.fillWidth:true;implicitHeight:44;placeholderText:"Absolute path to the SQLite outbox";selectByMouse:true;enabled:!publisher.busy}
                ActionButton {text:"Browse";enabled:!publisher.busy;onClicked:{picker.choosingKey=false;picker.open();}}
            }
            Label {text:"Key password"}
            TextField {id:keyPasswordInput;Layout.fillWidth:true;implicitHeight:44;echoMode:TextInput.Password;enabled:!publisher.busy;maximumLength:1024;inputMethodHints:Qt.ImhSensitiveData|Qt.ImhNoPredictiveText}
            Label {text:"Outbox password"}
            TextField {id:outboxPasswordInput;Layout.fillWidth:true;implicitHeight:44;echoMode:TextInput.Password;enabled:!publisher.busy;maximumLength:1024;inputMethodHints:Qt.ImhSensitiveData|Qt.ImhNoPredictiveText}
            ActionButton {text:"Unlock for publishing";primary:true;enabled:!publisher.busy&&panel.program.length>0&&keyPathInput.text.length>0&&outboxPathInput.text.length>0&&keyPasswordInput.text.length>0&&outboxPasswordInput.text.length>0;onClicked:panel.unlock()}
            Text {text:"Use an existing key vault and outbox created with maps-publish. Keys stay in the native publisher; passwords are cleared from this form after unlock is requested.";Layout.fillWidth:true;wrapMode:Text.Wrap;color:"#63715d";font.pixelSize:12;textFormat:Text.PlainText}
        }
        RowLayout {
            visible:publisher.unlocked
            Layout.fillWidth:true
            Text {text:"Signing account  "+publisher.author;Layout.fillWidth:true;wrapMode:Text.WrapAnywhere;color:"#395333";textFormat:Text.PlainText}
            ActionButton {text:"Lock";enabled:!publisher.busy;onClicked:publisher.lock()}
        }
        ColumnLayout {
            visible:publisher.unlocked && !publisher.review
            Layout.fillWidth:true
            Text {text:panel.snapshots.length ? "Stored snapshots · select regions for registration" : "No verified stored snapshots yet. Use Verify and store in File operations.";Layout.fillWidth:true;wrapMode:Text.Wrap;color:"#63715d";textFormat:Text.PlainText}
            RowLayout {
                ActionButton {text:"Select all";enabled:!publisher.busy&&panel.snapshots.length>0;onClicked:panel.chooseAll()}
                ActionButton {text:"Clear";enabled:!publisher.busy;onClicked:panel.selectedCids=[]}
            }
            Repeater {
                model:panel.snapshots
                delegate: CheckBox {
                    required property var modelData
                    readonly property string identity:modelData.region+"|"+modelData.cid+"|"+modelData.version
                    Layout.fillWidth:true;implicitHeight:48
                    text:modelData.region+" · "+modelData.version+" · stored"
                    checked:panel.selectedCids.indexOf(identity)>=0
                    enabled:!publisher.busy
                    onToggled:{var rows=panel.selectedCids.filter(function(v){return v!==identity;});if(checked)rows.push(identity);panel.selectedCids=rows;}
                }
            }
            Text {text:"Each step needs approval. The next step initializes the registry, creates a page, or registers up to eight snapshots within one page. After submission, check its saved transaction and review the next step. Only matching on-chain records are skipped.";Layout.fillWidth:true;wrapMode:Text.Wrap;color:"#63715d";textFormat:Text.PlainText}
            Label {text:"Maximum fee per transaction · native units"}
            TextField {id:cap;Layout.fillWidth:true;implicitHeight:44;text:"500000000";validator:RegularExpressionValidator{regularExpression:/[0-9]{1,39}/} enabled:!publisher.busy}
            Label {text:"Execution gas limit"}
            TextField {id:gas;Layout.fillWidth:true;implicitHeight:44;text:"10000000";validator:RegularExpressionValidator{regularExpression:/[0-9]{1,20}/} enabled:!publisher.busy}
            Label {text:"Tip · native units"}
            TextField {id:tip;Layout.fillWidth:true;implicitHeight:44;text:"0";validator:RegularExpressionValidator{regularExpression:/[0-9]{1,20}/} enabled:!publisher.busy}
            ActionButton {text:"Review next step ("+panel.selectedSnapshots.length+" selected)";primary:true;enabled:!publisher.busy&&panel.selectedSnapshots.length>0&&panel.selectedSnapshots.length<=72;onClicked:panel.prepare()}
        }
        Rectangle {
            visible:!!publisher.review
            Layout.fillWidth:true
            implicitHeight:reviewColumn.implicitHeight+32
            color:"#ffffff";radius:12
            ColumnLayout {
                id:reviewColumn
                anchors.left:parent.left;anchors.right:parent.right;anchors.top:parent.top;anchors.margins:16;spacing:12
                Text {Layout.fillWidth:true;wrapMode:Text.Wrap;textFormat:Text.PlainText;color:"#395333";text:!publisher.review ? "" : publisher.review.instruction==="Initialize" ? "Initialize the map registry. This does not register snapshots." : publisher.review.instruction.CreatePage ? "Create registry page "+publisher.review.instruction.CreatePage.number+". This does not register snapshots." : "Register the snapshots listed below. Other selected snapshots remain for later steps."}
                Text {text:"Review before signing";font.family:"Noto Serif";font.pixelSize:22;color:"#23482d";textFormat:Text.PlainText}
                Text {Layout.fillWidth:true;wrapMode:Text.WrapAnywhere;textFormat:Text.PlainText;color:"#395333";text:publisher.review ? "Registry: "+publisher.review.program+"\nNode: "+publisher.review.endpoint+"\nAccount: "+publisher.review.author+"\nNonce: "+publisher.review.nonce : ""}
                Repeater {
                    model:publisher.review ? publisher.review.snapshots || [] : []
                    delegate: Text {
                        required property var modelData
                        Layout.fillWidth:true;wrapMode:Text.WrapAnywhere;textFormat:Text.PlainText;color:"#395333"
                        text:modelData.region+" · "+modelData.version+" · "+modelData.bytes+" bytes\nCID: "+modelData.cid+"\nSource: "+modelData.source_url+"\nMD5: "+modelData.checksum.map(function(b){return ("0"+b.toString(16)).slice(-2);}).join("")
                    }
                }
                Text {Layout.fillWidth:true;wrapMode:Text.Wrap;textFormat:Text.PlainText;color:"#395333";text:publisher.review ? "Maximum fee: "+publisher.review.fee.max_fee+" native units\nQuoted reserve: "+publisher.review.quoted_reserve+" · quote block "+publisher.review.quote_height+"\nPayer balance: "+publisher.review.payer_balance+"\nGas limit: "+publisher.review.fee.gas_limit+" · Tip: "+publisher.review.fee.tip : ""}
                Text {Layout.fillWidth:true;wrapMode:Text.Wrap;textFormat:Text.PlainText;color:"#63715d";font.pixelSize:12;text:"The reserve is not a final fee prediction. Approval expires after two minutes; state, nonce, fees and balance are checked again before signing."}
                Flow {
                    Layout.fillWidth:true;spacing:8
                    ActionButton {text:"Approve and submit once";primary:true;enabled:!publisher.busy;onClicked:publisher.approve()}
                    ActionButton {text:"Cancel review";enabled:!publisher.busy;onClicked:publisher.cancel()}
                }
            }
        }
        ColumnLayout {
            visible:publisher.unlocked
            Layout.fillWidth:true
            Text {text:"Saved submissions";font.pixelSize:18;color:"#23482d";textFormat:Text.PlainText}
            ActionButton {text:"Refresh history";enabled:!publisher.busy;onClicked:publisher.refresh()}
            Repeater {
                model:publisher.history
                delegate: ColumnLayout {
                    required property var modelData
                    Layout.fillWidth:true
                    Text {Layout.fillWidth:true;wrapMode:Text.WrapAnywhere;textFormat:Text.PlainText;color:"#395333";text:parent.modelData.hash+"\n"+(parent.modelData.status==="observed" ? "Exact transaction observed · execution not verified here" : parent.modelData.status==="acknowledged" ? "Acknowledged by node · observation pending" : "Submission uncertain · recover this hash before any retry")}
                    ActionButton {text:"Check saved transaction";enabled:!publisher.busy;onClicked:publisher.reconcile(parent.modelData.hash)}
                }
            }
        }
        Item {Layout.preferredHeight:20}
    }
}
