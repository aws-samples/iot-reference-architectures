package com.awslabs.iatt.spe.serverless.gwt.shared;

import com.awslabs.iatt.spe.serverless.gwt.client.mqtt.ClientConfig;
import com.google.gwt.user.client.rpc.RemoteService;
import com.google.gwt.user.client.rpc.RemoteServiceRelativePath;

/**
 * The client side stub for the RPC service.
 */
@RemoteServiceRelativePath("jwt")
public interface JwtService extends RemoteService {
    JwtResponse getJwtResponse(String iccid, int expirationInMs);

    boolean isTokenValid(String token);

    ClientConfig getClientConfig();

    String getAuthorizerName();
}
