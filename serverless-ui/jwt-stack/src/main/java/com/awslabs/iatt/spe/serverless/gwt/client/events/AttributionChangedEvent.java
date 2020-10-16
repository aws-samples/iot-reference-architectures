package com.awslabs.iatt.spe.serverless.gwt.client.events;

import org.dominokit.domino.api.shared.extension.DominoEvent;

public class AttributionChangedEvent implements DominoEvent<AttributionData> {
    private final AttributionData attributionData;

    public AttributionChangedEvent(AttributionData attributionData) {
        this.attributionData = attributionData;
    }

    @Override
    public AttributionData context() {
        return attributionData;
    }
}
