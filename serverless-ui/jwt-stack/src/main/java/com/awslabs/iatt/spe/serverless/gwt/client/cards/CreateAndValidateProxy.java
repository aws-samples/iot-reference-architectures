package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.client.events.InvalidatedEvent;
import com.awslabs.iatt.spe.serverless.gwt.client.events.JwtChangedEvent;
import com.awslabs.iatt.spe.serverless.gwt.client.shell.ShellEvent;
import com.awslabs.iatt.spe.serverless.gwt.client.shell.ShellSlots;
import com.awslabs.iatt.spe.serverless.gwt.shared.JwtResponse;
import com.google.gwt.user.client.Window;
import com.google.gwt.user.client.rpc.AsyncCallback;
import org.dominokit.domino.api.client.annotations.presenter.*;
import org.dominokit.domino.api.client.mvp.presenter.ViewBaseClientPresenter;
import org.dominokit.domino.api.shared.extension.EventContext;
import org.dominokit.domino.ui.loaders.Loader;

import static com.awslabs.iatt.spe.serverless.gwt.client.BrowserHelper.danger;
import static com.awslabs.iatt.spe.serverless.gwt.client.BrowserHelper.success;
import static com.awslabs.iatt.spe.serverless.gwt.client.JwtEntryPoint.JWT_SERVICE_ASYNC;

@PresenterProxy
@Singleton
@AutoReveal
@AutoRoute
@Slot(ShellSlots.CREATE_AND_VALIDATE_TAB)
@DependsOn(@EventsGroup(ShellEvent.class))
public class CreateAndValidateProxy extends ViewBaseClientPresenter<CreateAndValidateView> implements CreateAndValidateView.CreateAndValidateUiHandlers {
    @Override
    public void requestJwt(Loader loader, String iccid, int expirationTimeMs) {
        JWT_SERVICE_ASYNC.getJwtResponse(iccid, expirationTimeMs, new AsyncCallback<JwtResponse>() {
                    @Override
                    public void onFailure(Throwable caught) {
                        loader.stop();
                        danger("Something went wrong: [" + caught + "]");
                    }

                    @Override
                    public void onSuccess(JwtResponse jwtResponse) {
                        loader.stop();
                        fireEvent(JwtChangedEvent.class, new JwtChangedEvent(jwtResponse));
                    }
                }
        );
    }

    @Override
    public void validateJwt(Loader loader, String token) {
        JWT_SERVICE_ASYNC.isTokenValid(token, new AsyncCallback<Boolean>() {
            @Override
            public void onFailure(Throwable caught) {
                loader.stop();
                Window.alert("Something went wrong: [" + caught + "]");
            }

            @Override
            public void onSuccess(Boolean result) {
                loader.stop();

                if (!result) {
                    danger("The JWT is not valid!");
                } else {
                    success("The JWT is valid!");
                }
            }
        });
    }

    @Override
    public void invalidate() {
        fireEvent(InvalidatedEvent.class, new InvalidatedEvent());
    }

    @ListenTo(event = JwtChangedEvent.class)
    public void onJwtChanged(JwtResponse jwtResponse) {
        view.onJwtChanged(jwtResponse);
    }

    @ListenTo(event = InvalidatedEvent.class)
    public void invalidated(EventContext eventContext) {
        view.onInvalidatedEvent();
    }
}