package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.shared.JwtResponse;
import org.dominokit.domino.api.client.mvp.view.ContentView;
import org.dominokit.domino.api.client.mvp.view.HasUiHandlers;
import org.dominokit.domino.api.client.mvp.view.UiHandlers;
import org.dominokit.domino.ui.loaders.Loader;

public interface CreateAndValidateView extends ContentView, HasUiHandlers<CreateAndValidateView.CreateAndValidateUiHandlers> {
    void onJwtChanged(JwtResponse jwtResponse);

    void onInvalidatedEvent();

    interface CreateAndValidateUiHandlers extends UiHandlers {
        void requestJwt(Loader loader, String stringValue, int expirationTimeMs);

        void validateJwt(Loader loader, String token);

        void invalidate();
    }
}