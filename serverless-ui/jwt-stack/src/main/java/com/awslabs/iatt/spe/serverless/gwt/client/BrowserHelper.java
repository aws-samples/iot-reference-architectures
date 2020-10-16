package com.awslabs.iatt.spe.serverless.gwt.client;

import elemental2.dom.ClipboardEvent;
import elemental2.dom.DomGlobal;
import elemental2.dom.EventListener;
import jsinterop.base.Js;
import org.dominokit.domino.ui.notifications.Notification;
import org.dominokit.domino.ui.utils.DominoDom;

public class BrowserHelper {
    public static void copyThis(String toCopy) {
        EventListener copyListener = e -> {
            ClipboardEvent clipboardEvent = Js.uncheckedCast(e);
            clipboardEvent.clipboardData.setData("text/plain", toCopy);
            e.preventDefault();
        };
        DomGlobal.document.addEventListener("copy", copyListener);
        DominoDom.document.execCommand("copy");
        DomGlobal.document.removeEventListener("copy", copyListener);
        success("Copied to clipboard");
    }

    public static void danger(String message) {
        danger(message, Notification.TOP_LEFT);
    }

    public static void danger(String message, Notification.Position position) {
        Notification.createDanger(message)
                .setPosition(position)
                .show();
    }

    public static void success(String message) {
        success(message, Notification.TOP_LEFT);
    }

    public static void success(String message, Notification.Position position) {
        Notification.createSuccess(message)
                .setPosition(position)
                .show();
    }
}
