package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.client.components.CodeCard;
import com.awslabs.iatt.spe.serverless.gwt.client.events.AttributionData;
import com.awslabs.iatt.spe.serverless.gwt.client.events.AuthorizerName;
import com.awslabs.iatt.spe.serverless.gwt.client.mqtt.MqttClient;
import com.awslabs.iatt.spe.serverless.gwt.shared.JwtResponse;
import elemental2.dom.HTMLDivElement;
import org.dominokit.domino.api.client.annotations.UiView;
import org.dominokit.domino.ui.cards.Card;
import org.dominokit.domino.ui.grid.Column;
import org.dominokit.domino.ui.grid.Row;
import org.dominokit.domino.ui.lists.ListGroup;
import org.dominokit.domino.ui.utils.BaseDominoElement;
import org.dominokit.domino.view.BaseElementView;

import java.util.*;

import static com.awslabs.iatt.spe.serverless.gwt.client.SharedWithServer.topicMqttWildcard;
import static org.jboss.elemento.Elements.h;

@UiView(presentable = TestProxy.class)
public class TestViewImpl extends BaseElementView<HTMLDivElement> implements TestView {
    private MqttClient mqttClient;
    private ListGroup<Map.Entry<String, String>> messages;
    private List<Map.Entry<String, String>> messageList;
    private Card mqttBufferCard;
    private CodeCard mosquittoCommandCard;
    private CodeCard awsCliCommandCard;
    private Optional<AuthorizerName> optionalAuthorizerName = Optional.empty();
    private Optional<AttributionData> optionalAttributionData = Optional.empty();
    private Optional<JwtResponse> optionalJwtResponse = Optional.empty();
    private TestUiHandlers uiHandlers;

    @Override
    protected HTMLDivElement init() {
        uiHandlers.getAuthorizerName();
        uiHandlers.getMqttClient();

        getMosquittoCommandCard();
        getAWSCLICommandCard();
        getMessagesListGroup();
        getMqttBufferCard();

        return Card.create("Test", "You can test JWTs on this tab")
                .appendChild(mosquittoCommandCard)
                .appendChild(awsCliCommandCard)
                .appendChild(mqttBufferCard)
                .element();
    }

    private void getMessagesListGroup() {
        messages = ListGroup.create();
        messageList = new ArrayList<>();

        messages.setItemRenderer((listGroup, item) -> {
            Map.Entry<String, String> entry = item.getValue();
            String topic = entry.getKey();
            String payload = entry.getValue();
            item.setSelectable(false);
            item.appendChild(Row.create()
                    .appendChild(Column.span2()
                            .appendChild(h(6).textContent(topic))
                            .appendChild(h(6).textContent(payload))
                    )
            );
        });
    }

    private void getMqttBufferCard() {
        mqttBufferCard = Card.create("Messages", "Live messages will show up here")
                .appendChild(messages);
    }

    private void getAWSCLICommandCard() {
        awsCliCommandCard = CodeCard.createCodeCard("")
                .setTitle("AWS CLI authorizer test command")
                .apply(BaseDominoElement::show);

        invalidateAwsCliCommandCard();
    }

    private void updateAwsCliCommandLine() {
        if (!optionalAuthorizerName.isPresent()) {
            // Can't update this without the authorizer name
            return;
        }

        if (!optionalJwtResponse.isPresent()) {
            // Can't update this without the JWT response
            return;
        }

        JwtResponse jwtResponse = optionalJwtResponse.get();

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("aws iot test-invoke-authorizer --mqtt-context \"{\\\"username\\\":\\\"");
        String splitToken = jwtResponse.token.replaceAll("(.{80})", "$1\\\\\n");
        stringBuilder.append(splitToken);

        if (optionalAttributionData.map(attributionData -> attributionData.attributionEnabled).orElse(false)) {
            stringBuilder.append("?");
            addAttributionData(stringBuilder);
        }

        stringBuilder.append("\\\"}\"\\\n");
        stringBuilder.append(" --authorizer-name ");
        stringBuilder.append(optionalAuthorizerName.get().value);

        awsCliCommandCard.setCode(stringBuilder.toString());
    }

    private void addAttributionData(StringBuilder stringBuilder) {
        AttributionData attributionData = optionalAttributionData.get();

        String platformValue = "APN/1 " + attributionData.partnerName;

        if (!attributionData.solutionName.isEmpty()) {
            platformValue += "," + attributionData.solutionName;
        }

        if (!attributionData.versionName.isEmpty()) {
            platformValue += "," + attributionData.versionName;
        }

        stringBuilder.append("Platform=" + platformValue);
    }

    private void getMosquittoCommandCard() {
        mosquittoCommandCard = CodeCard.createCodeCard("")
                .setTitle("Mosquitto publish command")
                .apply(BaseDominoElement::show);

        invalidateMosquitoCommandCard();
    }

    private void invalidate() {
        invalidateMosquitoCommandCard();
        invalidateAwsCliCommandCard();
    }

    private void invalidateMosquitoCommandCard() {
        mosquittoCommandCard.setCode("Not generated yet");
    }

    private void invalidateAwsCliCommandCard() {
        awsCliCommandCard.setCode("Not generated yet");
    }

    private void updateMosquittoCommandLine() {
        if (!optionalAuthorizerName.isPresent()) {
            // Can't update this without the authorizer name
            return;
        }

        if (!optionalJwtResponse.isPresent()) {
            // Can't update this without the JWT response
            return;
        }

        JwtResponse jwtResponse = optionalJwtResponse.get();

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("bash -c \"mosquitto_pub -d --tls-alpn mqtt \\\n");
        stringBuilder.append("  -h " + jwtResponse.endpoint + " \\\n");
        stringBuilder.append("  -p 443 \\\n");
        stringBuilder.append("  -i " + jwtResponse.iccid + " \\\n");
        stringBuilder.append("  -t clients/jwt/" + jwtResponse.iccid + " \\\n");
        stringBuilder.append("  -m 'Message from " + jwtResponse.iccid + "' \\\n");
        String splitToken = jwtResponse.token.replaceAll("(.{80})", "$1\\\\\n");
        stringBuilder.append("  -u '" + splitToken);

        stringBuilder.append("?x-amz-customauthorizer-name=");
        stringBuilder.append(optionalAuthorizerName.get().value);

        if (optionalAttributionData.map(attributionData -> attributionData.attributionEnabled).orElse(false)) {
            stringBuilder.append("&");
            addAttributionData(stringBuilder);
        }

        stringBuilder.append("' \\\n");
        stringBuilder.append("  --cafile <(curl https://www.amazontrust.com/repository/AmazonRootCA1.pem)\"");

        mosquittoCommandCard.setCode(stringBuilder.toString());
    }

    private void addRowAndUpdate(String topic, Object payload) {
        String payloadString = payload.toString();

        messageList.add(0, new AbstractMap.SimpleEntry<>(topic, payloadString));

        while (messageList.size() > 7) {
            messageList.remove(messageList.size() - 1);
        }

        messages.setItems(messageList);
    }

    @Override
    public void onJwtChanged(JwtResponse jwtResponse) {
        this.optionalJwtResponse = Optional.of(jwtResponse);

        updateAll();
    }

    @Override
    public void onAttributionChanged(AttributionData attributionData) {
        this.optionalAttributionData = Optional.empty();

        if (attributionData.attributionEnabled) {
            this.optionalAttributionData = Optional.of(attributionData);
        }

        updateAll();
    }

    private void updateAll() {
        invalidate();

        updateAwsCliCommandLine();
        updateMosquittoCommandLine();
    }

    @Override
    public void onAuthorizerNameUpdated(AuthorizerName authorizerName) {
        optionalAuthorizerName = Optional.of(authorizerName);
    }

    @Override
    public void onInvalidatedEvent() {
        optionalJwtResponse = Optional.empty();

        invalidate();
    }

    @Override
    public void setMqttClient(MqttClient mqttClient) {
        this.mqttClient = mqttClient;
        this.mqttClient.subscribe(topicMqttWildcard);
        this.mqttClient.onMessageCallback(this::addRowAndUpdate);

        this.mqttClient.onConnectCallback(() -> addRowAndUpdate("Connected", "..."));
        mqttClient.onReconnectCallback(() -> addRowAndUpdate("Reconnected", "..."));
        mqttClient.onOfflineCallback(() -> addRowAndUpdate("Offline", "..."));
        mqttClient.onErrorCallback(error -> addRowAndUpdate("Error", error));
    }

    @Override
    public void setUiHandlers(TestUiHandlers uiHandlers) {
        this.uiHandlers = uiHandlers;
    }
}