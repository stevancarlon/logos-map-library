// SPDX-License-Identifier: MIT OR Apache-2.0
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
ScrollView {
    id: panel
    required property var control
    required property var paths
    property var excluded: []
    property alias downloadDirectory: directory.text
    property alias maximumBytes: limit.text
    readonly property var selected: paths.filter(function(p) {return excluded.indexOf(p)<0;})
    contentWidth: availableWidth
    clip: true
    function source(path) {return control.updates.find(function(u) {return u.source.region===path;});}
    function begin() {
        var items=selected.map(function(path) {
            return {region:path,version:source(path).source.version,selected:true,
                input:{kind:"fetch",destination:directory.text.replace(/\/$/,"")+"/"+path.replace(/\//g,"-")+"-"+source(path).source.version+".osm.pbf"}};
        });
        control.start({op:"store_bulk",items:items,limit:limit.text});
    }
    FolderDialog {
        id: folder
        title: "Choose a directory for downloaded extracts"
        onAccepted: directory.text=decodeURIComponent(selectedFolder.toString().replace(/^file:\/\//,""))
    }
    ColumnLayout {
        width: panel.availableWidth
        spacing: 14
        Text {text:"Host selected regions";font.family:"Noto Serif";font.pixelSize:26;color:"#23482d";Layout.fillWidth:true;wrapMode:Text.Wrap}
        Text {text:"Select regions in Library, then opt out below. Refresh source dates before starting. Downloads and uploads run one at a time; each successful snapshot is saved for review in Publishing.";Layout.fillWidth:true;wrapMode:Text.Wrap;color:"#63715d";textFormat:Text.PlainText}
        RowLayout {
            ActionButton {text:"Refresh source dates";enabled:!panel.control.state.running&&panel.paths.length>0;onClicked:panel.control.checkUpdates(panel.paths)}
            Text {text:panel.selected.length+" selected";color:"#395333"}
        }
        Repeater {
            model:panel.paths
            delegate: CheckBox {
                required property string modelData
                Layout.fillWidth:true
                implicitHeight:44
                text:modelData+" · "+(panel.source(modelData) ? panel.source(modelData).source.version : "source date not checked")
                checked:panel.excluded.indexOf(modelData)<0
                enabled:!panel.control.state.running
                onToggled: {var rows=panel.excluded.filter(function(p){return p!==modelData;});if(!checked)rows.push(modelData);panel.excluded=rows;}
            }
        }
        Label {text:"Download directory"}
        RowLayout {
            Layout.fillWidth:true
            TextField {id:directory;Layout.fillWidth:true;implicitHeight:44;placeholderText:"Absolute directory path";enabled:!panel.control.state.running;Accessible.name:"Download directory"}
            ActionButton {text:"Browse";enabled:!panel.control.state.running;onClicked:folder.open()}
        }
        Label {text:"Maximum bytes per region"}
        TextField {id:limit;text:"10000000000";Layout.fillWidth:true;implicitHeight:44;enabled:!panel.control.state.running;validator:RegularExpressionValidator{regularExpression:/[0-9]{1,12}/} Accessible.name:"Maximum bytes per region"}
        Text {text:"Files use region and snapshot date in their names. Existing files are never overwritten. Uploads are public and can remain in Storage after cancellation. This step does not register them.";Layout.fillWidth:true;wrapMode:Text.Wrap;color:"#63715d";textFormat:Text.PlainText}
        ActionButton {
            text:"Fetch and store "+panel.selected.length+" regions"
            primary:true
            enabled:!panel.control.state.running&&directory.text.startsWith("/")&&panel.selected.length>0&&panel.selected.every(function(p){return !!panel.source(p);})
            onClicked:panel.begin()
        }
        Repeater {
            model:panel.control.state.bulk_outcomes || []
            delegate: Text {
                required property var modelData
                Layout.fillWidth:true;wrapMode:Text.WrapAnywhere;textFormat:Text.PlainText
                color:modelData.state==="stored" ? "#395333" : "#8b4327"
                text:modelData.state==="stored" ? modelData.snapshot.region+" · stored · "+modelData.snapshot.cid : modelData.region+" · failed · "+modelData.error
            }
        }
    }
}
