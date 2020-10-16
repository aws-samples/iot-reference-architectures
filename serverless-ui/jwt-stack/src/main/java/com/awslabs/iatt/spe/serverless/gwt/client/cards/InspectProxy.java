package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.client.events.InvalidatedEvent;
import com.awslabs.iatt.spe.serverless.gwt.client.events.JwtChangedEvent;
import com.awslabs.iatt.spe.serverless.gwt.client.shell.ShellEvent;
import com.awslabs.iatt.spe.serverless.gwt.client.shell.ShellSlots;
import com.awslabs.iatt.spe.serverless.gwt.shared.JwtResponse;
import org.dominokit.domino.api.client.annotations.presenter.*;
import org.dominokit.domino.api.client.mvp.presenter.ViewBaseClientPresenter;
import org.dominokit.domino.api.shared.extension.EventContext;

@PresenterProxy
@Singleton
@AutoReveal
@AutoRoute
@Slot(ShellSlots.INSPECT_TAB)
@DependsOn(@EventsGroup(ShellEvent.class))
public class InspectProxy extends ViewBaseClientPresenter<InspectView> implements InspectView.InspectUiHandlers {
    @ListenTo(event = JwtChangedEvent.class)
    public void onJwtChanged(JwtResponse jwtResponse) {
        view.onJwtChanged(jwtResponse);
    }

    @ListenTo(event = InvalidatedEvent.class)
    public void invalidated(EventContext eventContext) {
        view.onInvalidatedEvent();
    }
}
