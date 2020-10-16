package com.awslabs.iatt.spe.serverless.gwt.client.shell;

import org.dominokit.domino.api.client.mvp.view.ContentView;
import org.dominokit.domino.api.client.mvp.view.HasUiHandlers;
import org.dominokit.domino.api.client.mvp.view.UiHandlers;

public interface ShellView extends ContentView, HasUiHandlers<ShellView.ShellUiHandlers>, ShellProxySlots {
    void activatePage(String page);

    interface ShellUiHandlers extends UiHandlers {
        void onNavigation(String token);
    }
}