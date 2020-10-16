package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.client.events.*;
import com.awslabs.iatt.spe.serverless.gwt.client.mqtt.AWSIoTData;
import com.awslabs.iatt.spe.serverless.gwt.client.mqtt.ClientConfig;
import com.awslabs.iatt.spe.serverless.gwt.client.mqtt.MqttClient;
import com.awslabs.iatt.spe.serverless.gwt.client.shell.ShellEvent;
import com.awslabs.iatt.spe.serverless.gwt.client.shell.ShellSlots;
import com.awslabs.iatt.spe.serverless.gwt.shared.JwtResponse;
import com.google.gwt.json.client.JSONBoolean;
import com.google.gwt.json.client.JSONNumber;
import com.google.gwt.json.client.JSONObject;
import com.google.gwt.json.client.JSONString;
import com.google.gwt.user.client.Window;
import com.google.gwt.user.client.rpc.AsyncCallback;
import org.dominokit.domino.api.client.annotations.presenter.*;
import org.dominokit.domino.api.client.mvp.presenter.ViewBaseClientPresenter;
import org.dominokit.domino.api.shared.extension.EventContext;

import static com.awslabs.iatt.spe.serverless.gwt.client.BrowserHelper.danger;
import static com.awslabs.iatt.spe.serverless.gwt.client.JwtEntryPoint.JWT_SERVICE_ASYNC;

@PresenterProxy
@Singleton
@AutoReveal
@AutoRoute
@Slot(ShellSlots.TEST_TAB)
@DependsOn(@EventsGroup(ShellEvent.class))
public class TestProxy extends ViewBaseClientPresenter<TestView> implements TestView.TestUiHandlers {
    public static final String WEBSOCKET_PROTOCOL = "wss";

    @ListenTo(event = InvalidatedEvent.class)
    public void invalidated(EventContext eventContext) {
        view.onInvalidatedEvent();
    }

    @ListenTo(event = AttributionChangedEvent.class)
    public void attributionChanged(AttributionData attributionData) {
        view.onAttributionChanged(attributionData);
    }

    @ListenTo(event = JwtChangedEvent.class)
    public void jwtChanged(JwtResponse jwtResponse) {
        view.onJwtChanged(jwtResponse);
    }

    @Override
    public void getAuthorizerName() {
        JWT_SERVICE_ASYNC.getAuthorizerName(new AsyncCallback<String>() {
            @Override
            public void onFailure(Throwable caught) {
                danger("Couldn't get authorizer name, MQTT command and AWS CLI command cards will not update [" + caught.getMessage() + "]");
            }

            @Override
            public void onSuccess(String result) {
                view.onAuthorizerNameUpdated(new AuthorizerName(result));
            }
        });
    }

    @Override
    public void getMqttClient() {
        JWT_SERVICE_ASYNC.getClientConfig(new AsyncCallback<ClientConfig>() {
            @Override
            public void onFailure(Throwable caught) {
                Window.alert("Couldn't get credentials [" + caught.getMessage() + "]");
            }

            @Override
            public void onSuccess(ClientConfig clientConfig) {
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("region", new JSONString(clientConfig.region));
                jsonObject.put("host", new JSONString(clientConfig.endpointAddress));
                jsonObject.put("clientId", new JSONString(clientConfig.clientId));
                jsonObject.put("protocol", new JSONString(WEBSOCKET_PROTOCOL));
                jsonObject.put("maximumReconnectTimeMs", new JSONNumber(8000));
                jsonObject.put("debug", JSONBoolean.getInstance(true));
                jsonObject.put("accessKeyId", new JSONString(clientConfig.accessKeyId));
                jsonObject.put("secretKey", new JSONString(clientConfig.secretAccessKey));
                jsonObject.put("sessionToken", new JSONString(clientConfig.sessionToken));

                MqttClient mqttClient = AWSIoTData.device(jsonObject.getJavaScriptObject());

                view.setMqttClient(mqttClient);
            }
        });
    }
}
