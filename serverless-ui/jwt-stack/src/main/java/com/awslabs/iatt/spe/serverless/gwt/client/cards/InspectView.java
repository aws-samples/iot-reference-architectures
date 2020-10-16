package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.shared.JwtResponse;
import org.dominokit.domino.api.client.mvp.view.ContentView;
import org.dominokit.domino.api.client.mvp.view.HasUiHandlers;
import org.dominokit.domino.api.client.mvp.view.UiHandlers;

public interface InspectView extends ContentView, HasUiHandlers<InspectView.InspectUiHandlers> {
    void onJwtChanged(JwtResponse jwtResponse);

    void onInvalidatedEvent();

    interface InspectUiHandlers extends UiHandlers {
    }
}