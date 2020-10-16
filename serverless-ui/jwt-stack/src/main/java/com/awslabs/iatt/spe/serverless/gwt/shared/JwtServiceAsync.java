package com.awslabs.iatt.spe.serverless.gwt.shared;

import com.awslabs.iatt.spe.serverless.gwt.client.mqtt.ClientConfig;
import com.google.gwt.user.client.rpc.AsyncCallback;

public interface JwtServiceAsync {
    void getJwtResponse(String iccid, int expirationInMs, AsyncCallback<JwtResponse> async);

    void isTokenValid(String token, AsyncCallback<Boolean> async);

    void getClientConfig(AsyncCallback<ClientConfig> async);

    void getAuthorizerName(AsyncCallback<String> async);
}
