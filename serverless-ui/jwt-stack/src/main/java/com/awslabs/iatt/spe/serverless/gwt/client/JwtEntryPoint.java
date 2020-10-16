package com.awslabs.iatt.spe.serverless.gwt.client;

import com.awslabs.iatt.spe.serverless.gwt.shared.JwtService;
import com.awslabs.iatt.spe.serverless.gwt.shared.JwtServiceAsync;
import com.google.gwt.core.client.EntryPoint;
import com.google.gwt.core.client.GWT;
import org.dominokit.domino.api.client.ClientApp;
import org.dominokit.domino.api.client.ModuleConfigurator;
import org.dominokit.domino.api.client.annotations.ClientModule;
import org.dominokit.domino.gwt.client.app.DominoGWT;
import org.dominokit.domino.view.GwtView;

import java.util.logging.Logger;

@ClientModule(name = "Jwt")
public class JwtEntryPoint implements EntryPoint {
    public static final JwtServiceAsync JWT_SERVICE_ASYNC = GWT.create(JwtService.class);
    private static final Logger log = Logger.getLogger(JwtEntryPoint.class.getName());

    @Override
    public void onModuleLoad() {
        new ModuleConfigurator().configureModule(new JwtModuleConfiguration());
        DominoGWT.init();
        GwtView.init();
        ClientApp.make().run();
        log.info("Application initialized");
    }
}