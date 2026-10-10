// SPDX-License-Identifier: MIT OR Apache-2.0
import QtQuick
import QtQuick.Controls

Button {
    id: button
    property bool primary: false
    implicitHeight: 42
    implicitWidth: Math.max(90, label.implicitWidth + 28)
    hoverEnabled: true
    padding: 12
    contentItem: Text {
        id: label
        text: button.text
        color: !button.enabled ? "#8b948b" : button.primary ? "#ffffff" : "#244733"
        font.pixelSize: 13
        font.weight: Font.DemiBold
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }
    background: Rectangle {
        radius: 6
        color: !button.enabled ? "#e4e7df" : button.primary ? (button.down ? "#173522" : button.hovered ? "#28563a" : "#21492f") : (button.hovered ? "#e0e7dc" : "#edf0e8")
        border.color: button.activeFocus ? "#547b4b" : "transparent"
        border.width: 2
    }
}
