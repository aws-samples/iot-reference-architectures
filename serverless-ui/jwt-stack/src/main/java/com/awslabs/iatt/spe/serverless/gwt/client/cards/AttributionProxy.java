package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.client.events.AttributionChangedEvent;
import com.awslabs.iatt.spe.serverless.gwt.client.events.AttributionData;
import com.awslabs.iatt.spe.serverless.gwt.client.shell.ShellEvent;
import com.awslabs.iatt.spe.serverless.gwt.client.shell.ShellSlots;
import org.dominokit.domino.api.client.annotations.presenter.*;
import org.dominokit.domino.api.client.mvp.presenter.ViewBaseClientPresenter;

@PresenterProxy
@Singleton
@AutoReveal
@AutoRoute
@Slot(ShellSlots.ATTRIBUTION_TAB)
@DependsOn(@EventsGroup(ShellEvent.class))
public class AttributionProxy extends ViewBaseClientPresenter<AttributionView> implements AttributionView.AttributionUiHandlers {
    @Override
    public void onAttributionDataUpdated(AttributionData attributionData) {
        fireEvent(AttributionChangedEvent.class, new AttributionChangedEvent(attributionData));
    }
}
