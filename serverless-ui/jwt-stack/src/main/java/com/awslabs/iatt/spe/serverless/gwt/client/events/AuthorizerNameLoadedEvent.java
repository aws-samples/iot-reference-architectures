package com.awslabs.iatt.spe.serverless.gwt.client.events;

import org.dominokit.domino.api.shared.extension.DominoEvent;

public class AuthorizerNameLoadedEvent implements DominoEvent<AuthorizerName> {
    private final AuthorizerName authorizerName;

    public AuthorizerNameLoadedEvent(AuthorizerName authorizerName) {
        this.authorizerName = authorizerName;
    }

    @Override
    public AuthorizerName context() {
        return authorizerName;
    }
}
