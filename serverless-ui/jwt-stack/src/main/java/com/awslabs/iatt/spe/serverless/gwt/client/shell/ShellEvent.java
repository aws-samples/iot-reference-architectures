package com.awslabs.iatt.spe.serverless.gwt.client.shell;

import org.dominokit.domino.api.shared.extension.ActivationEvent;

public class ShellEvent extends ActivationEvent {
    public ShellEvent(boolean active) {
        super(active);
    }

    public ShellEvent(String serializedEvent) {
        super(serializedEvent);
    }
}
