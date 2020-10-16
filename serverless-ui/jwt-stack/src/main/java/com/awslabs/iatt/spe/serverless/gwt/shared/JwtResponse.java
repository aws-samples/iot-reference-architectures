package com.awslabs.iatt.spe.serverless.gwt.shared;

import com.google.gwt.user.client.rpc.IsSerializable;
import org.dominokit.domino.api.shared.extension.EventContext;

@SuppressWarnings("serial")
public class JwtResponse extends NoToString implements IsSerializable, EventContext {
    public String token;

    public String decodedJwt;

    public String iccid;

    public String endpoint;
}