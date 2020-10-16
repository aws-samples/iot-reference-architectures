package com.awslabs.iatt.spe.serverless.gwt.client.events;

import com.awslabs.iatt.spe.serverless.gwt.shared.NoToString;
import org.dominokit.domino.api.shared.extension.EventContext;

public class AttributionData extends NoToString implements EventContext {
    public final boolean attributionEnabled;
    public final String partnerName;
    public final String solutionName;
    public final String versionName;

    public AttributionData(boolean attributionEnabled, String partnerName, String solutionName, String versionName) {
        this.attributionEnabled = attributionEnabled;
        this.partnerName = partnerName;
        this.solutionName = solutionName;
        this.versionName = versionName;
    }
}
