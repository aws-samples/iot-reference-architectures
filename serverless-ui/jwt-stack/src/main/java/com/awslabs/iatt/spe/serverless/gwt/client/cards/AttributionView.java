package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.client.events.AttributionData;
import org.dominokit.domino.api.client.mvp.view.ContentView;
import org.dominokit.domino.api.client.mvp.view.HasUiHandlers;
import org.dominokit.domino.api.client.mvp.view.UiHandlers;

public interface AttributionView extends ContentView, HasUiHandlers<AttributionView.AttributionUiHandlers> {
    interface AttributionUiHandlers extends UiHandlers {
        void onAttributionDataUpdated(AttributionData attributionData);
    }
}