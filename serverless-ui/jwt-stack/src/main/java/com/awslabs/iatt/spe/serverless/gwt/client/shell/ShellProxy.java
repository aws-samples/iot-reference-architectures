package com.awslabs.iatt.spe.serverless.gwt.client.shell;

import com.awslabs.iatt.spe.serverless.gwt.client.PageTokenFilter;
import org.dominokit.domino.api.client.annotations.presenter.*;
import org.dominokit.domino.api.client.mvp.presenter.ViewBaseClientPresenter;
import org.dominokit.domino.api.shared.extension.PredefinedSlots;

@PresenterProxy
@AutoRoute(routeOnce = true)
@Slot(PredefinedSlots.BODY_SLOT)
@AutoReveal
@Singleton
@OnStateChanged(ShellEvent.class)
@RegisterSlots({ShellSlots.CREATE_AND_VALIDATE_TAB, ShellSlots.ATTRIBUTION_TAB, ShellSlots.INSPECT_TAB, ShellSlots.TEST_TAB})
public class ShellProxy extends ViewBaseClientPresenter<ShellView> implements ShellView.ShellUiHandlers {
    @OnReveal
    public void activateFirstTabByDefault() {
        if (history().currentToken().hasQueryParameter("page")) {
            view.activatePage(history().currentToken().getQueryParameter("page"));
            return;
        }

        onNavigation(ShellSlots.CREATE_AND_VALIDATE_TAB);
    }

    @Override
    public void onNavigation(String token) {
        if (history().currentToken().hasQueryParameter(PageTokenFilter.PAGE)) {
            history().fireState(history().currentToken().replaceParameter(PageTokenFilter.PAGE, PageTokenFilter.PAGE, token).value());
        } else {
            history().fireState(history().currentToken().appendParameter(PageTokenFilter.PAGE, token).value());
        }
    }
}