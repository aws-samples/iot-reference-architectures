package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.client.events.AttributionData;
import com.awslabs.iatt.spe.serverless.gwt.client.events.AuthorizerName;
import com.awslabs.iatt.spe.serverless.gwt.client.mqtt.MqttClient;
import com.awslabs.iatt.spe.serverless.gwt.shared.JwtResponse;
import org.dominokit.domino.api.client.mvp.view.ContentView;
import org.dominokit.domino.api.client.mvp.view.HasUiHandlers;
import org.dominokit.domino.api.client.mvp.view.UiHandlers;

public interface TestView extends ContentView, HasUiHandlers<TestView.TestUiHandlers> {
    void onJwtChanged(JwtResponse jwtResponse);

    void onAttributionChanged(AttributionData attributionData);

    void onAuthorizerNameUpdated(AuthorizerName authorizerName);

    void onInvalidatedEvent();

    void setMqttClient(MqttClient mqttClient);

    interface TestUiHandlers extends UiHandlers {
        void getAuthorizerName();

        void getMqttClient();
    }
}