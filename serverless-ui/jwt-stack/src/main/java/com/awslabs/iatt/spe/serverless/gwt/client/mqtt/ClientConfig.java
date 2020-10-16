package com.awslabs.iatt.spe.serverless.gwt.client.mqtt;

import com.google.gwt.user.client.rpc.IsSerializable;

public class ClientConfig implements IsSerializable {
    public String accessKeyId;
    public String secretAccessKey;
    public String sessionToken;
    public String endpointAddress;
    public String region;
    public String clientId;
}
