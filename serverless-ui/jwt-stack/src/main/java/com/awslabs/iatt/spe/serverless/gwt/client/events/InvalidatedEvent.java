package com.awslabs.iatt.spe.serverless.gwt.client.events;

import org.dominokit.domino.api.shared.extension.DominoEvent;
import org.dominokit.domino.api.shared.extension.EventContext;

public class InvalidatedEvent implements DominoEvent {
    @Override
    public EventContext context() {
        return null;
    }
}
