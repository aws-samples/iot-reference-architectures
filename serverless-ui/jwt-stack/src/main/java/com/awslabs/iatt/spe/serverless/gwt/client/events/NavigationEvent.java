package com.awslabs.iatt.spe.serverless.gwt.client.events;

import org.dominokit.domino.api.shared.extension.DominoEvent;
import org.dominokit.domino.api.shared.extension.EventContext;

public class NavigationEvent implements DominoEvent<NavigationEvent.NavigationContext> {
    private final NavigationContext context;

    public NavigationEvent(String token) {
        this.context = new NavigationContext(token);
    }

    @Override
    public NavigationContext context() {
        return context;
    }

    public static class NavigationContext implements EventContext {
        private final String navigationToken;

        public NavigationContext(String navigationToken) {
            this.navigationToken = navigationToken;
        }

        public String getNavigationToken() {
            return navigationToken;
        }
    }
}
