package com.awslabs.iatt.spe.serverless.gwt.client.events;

import com.awslabs.iatt.spe.serverless.gwt.shared.NoToString;
import org.dominokit.domino.api.shared.extension.EventContext;

public class AuthorizerName extends NoToString implements EventContext {
    public final String value;

    public AuthorizerName(String value) {
        this.value = value;
    }
}