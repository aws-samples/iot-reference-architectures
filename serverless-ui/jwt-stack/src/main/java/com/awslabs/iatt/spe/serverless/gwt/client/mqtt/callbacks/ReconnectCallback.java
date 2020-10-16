package com.awslabs.iatt.spe.serverless.gwt.client.mqtt.callbacks;

import jsinterop.annotations.JsFunction;

@JsFunction
public interface ReconnectCallback {
    void onReconnect();
}
