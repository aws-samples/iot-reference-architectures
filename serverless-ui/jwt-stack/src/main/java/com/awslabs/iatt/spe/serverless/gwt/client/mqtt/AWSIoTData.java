package com.awslabs.iatt.spe.serverless.gwt.client.mqtt;

import com.google.gwt.core.client.JavaScriptObject;
import jsinterop.annotations.JsPackage;
import jsinterop.annotations.JsType;

@JsType(isNative = true, namespace = JsPackage.GLOBAL)
public class AWSIoTData {
    public static native MqttClient device(JavaScriptObject deviceOptions);
}
