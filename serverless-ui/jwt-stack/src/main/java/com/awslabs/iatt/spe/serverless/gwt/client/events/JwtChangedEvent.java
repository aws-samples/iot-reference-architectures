package com.awslabs.iatt.spe.serverless.gwt.client.events;

import com.awslabs.iatt.spe.serverless.gwt.shared.JwtResponse;
import org.dominokit.domino.api.shared.extension.DominoEvent;

public class JwtChangedEvent implements DominoEvent<JwtResponse> {
    private final JwtResponse jwtResponse;

    public JwtChangedEvent(JwtResponse jwtResponse) {
        this.jwtResponse = jwtResponse;
    }

    @Override
    public JwtResponse context() {
        return jwtResponse;
    }
}
