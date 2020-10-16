package com.awslabs.iatt.spe.serverless.gwt.client.mqtt;

import com.awslabs.iatt.spe.serverless.gwt.client.mqtt.callbacks.*;
import jsinterop.annotations.JsOverlay;
import jsinterop.annotations.JsType;

@JsType(isNative = true)
public class MqttClient {
    @JsOverlay
    public final void onMessageCallback(MessageCallback messageCallback) {
        on("message", messageCallback);
    }

    @JsOverlay
    public final void onConnectCallback(ConnectCallback connectCallback) {
        on("connect", connectCallback);
    }

    @JsOverlay
    public final void onReconnectCallback(ReconnectCallback reconnectCallback) {
        on("reconnect", reconnectCallback);
    }

    @JsOverlay
    public final void onOfflineCallback(OfflineCallback offlineCallback) {
        on("offline", offlineCallback);
    }

    @JsOverlay
    public final void onErrorCallback(ErrorCallback errorCallback) {
        on("error", errorCallback);
    }

    public native void on(String eventType, MessageCallback messageCallback);

    public native void on(String eventType, ConnectCallback connectCallback);

    public native void on(String eventType, ReconnectCallback reconnectCallback);

    public native void on(String eventType, OfflineCallback offlineCallback);

    public native void on(String eventType, ErrorCallback errorCallback);

    public native void publish(String topic, String payload);

    public native void subscribe(String topic);
}
