package com.awslabs.iatt.spe.serverless.gwt.server;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.aws.samples.cdk.constructs.iam.permissions.HasIamPermissions;
import com.aws.samples.cdk.constructs.iam.permissions.IamPermission;
import com.aws.samples.cdk.constructs.iam.permissions.SharedPermissions;
import com.aws.samples.cdk.constructs.iam.permissions.iot.IotActions;
import com.aws.samples.cdk.constructs.iam.permissions.iot.IotResources;
import com.aws.samples.lambda.servlet.LambdaWebServlet;
import com.awslabs.iatt.spe.serverless.gwt.client.mqtt.ClientConfig;
import com.awslabs.iatt.spe.serverless.gwt.shared.JwtResponse;
import com.awslabs.iatt.spe.serverless.gwt.shared.JwtService;
import com.google.gwt.user.server.rpc.RemoteServiceServlet;
import io.vavr.control.Try;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.iot.IotClient;
import software.amazon.awssdk.services.iot.model.DescribeEndpointRequest;
import software.amazon.awssdk.services.iot.model.DescribeEndpointResponse;
import software.amazon.awssdk.services.iotdataplane.IotDataPlaneClient;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.Credentials;

import javax.servlet.annotation.WebServlet;
import java.net.URI;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static com.awslabs.iatt.spe.serverless.gwt.client.SharedWithServer.topicPrefix;
import static com.awslabs.iatt.spe.serverless.gwt.server.Authorizer.*;

/**
 * The server side implementation of the RPC service.
 */
@SuppressWarnings({"serial", "GwtServiceNotRegistered"})
@WebServlet(name = "JwtService", displayName = "BasicJwtService", urlPatterns = {"/app/jwt"}, loadOnStartup = 1)
@LambdaWebServlet
public class BasicJwtService extends RemoteServiceServlet implements JwtService, HasIamPermissions {
    public static final String APN = "APN";
    public static final String AUTHORIZERS = "AUTHORIZERS";
    public static final String DELIMITER = "/";
    private static final Logger log = Logger.getLogger(BasicJwtService.class);
    private static final String ICCID_KEY = "iccid";
    private static final int EXPIRATION_IN_MS_MIN = 10000;
    private static final int EXPIRATION_IN_MS_MAX = 120000;
    private static final String endpoint = IotClient.create().describeEndpoint(r -> r.endpointType("iot:Data-ATS")).endpointAddress();
    private static final StsClient stsClient = StsClient.create();
    private Optional<IotDataPlaneClient> optionalIotDataPlaneClient;

    @Override
    public JwtResponse getJwtResponse(String iccid, int expirationInMs) {
        if (expirationInMs < EXPIRATION_IN_MS_MIN) {
            throw new RuntimeException("Expiration time is below the minimum [" + EXPIRATION_IN_MS_MIN + "]");
        }

        if (expirationInMs > EXPIRATION_IN_MS_MAX) {
            throw new RuntimeException("Expiration time is above the maximum [" + EXPIRATION_IN_MS_MAX + "]");
        }

        Algorithm algorithm = getTokenSigner();
        JwtResponse jwtResponse = new JwtResponse();

        try {
            String token = JWT.create()
                    .withIssuer(APN)
                    .withClaim(ICCID_KEY, iccid)
                    .withExpiresAt(new Date(System.currentTimeMillis() + expirationInMs))
                    .withIssuedAt(new Date(System.currentTimeMillis()))
                    .sign(algorithm);

            jwtResponse.token = token;
            jwtResponse.decodedJwt = GsonHelper.toJson(extractDataToMap(token));
            jwtResponse.iccid = iccid;
            jwtResponse.endpoint = endpoint;
        } catch (JWTCreationException exception) {
            throw new RuntimeException(exception);
        }

        return jwtResponse;
    }

    @NotNull
    private Algorithm getTokenSigner() {
        RSAPublicKey publicKey = getRSAPublicKey(this.getServletContext());
        RSAPrivateKey privateKey = getRSAPrivateKey(this.getServletContext());

        return Algorithm.RSA256(publicKey, privateKey);
    }

    private Map extractDataToMap(String token) {
        DecodedJWT decodedJWT = extractData(this.getServletContext(), token);
        Map claimMap = new HashMap();
        decodedJWT.getClaims().entrySet().forEach(entry -> claimMap.put(entry.getKey(), entry.getValue().asString()));
        Map output = new HashMap();
        output.put("subject", decodedJWT.getSubject());
        output.put("claims", claimMap);
        output.put("payload", decodedJWT.getPayload());
        output.put("expiresAt", decodedJWT.getExpiresAt());
        output.put("header", decodedJWT.getHeader());
        output.put("signature", decodedJWT.getSignature());

        return output;
    }

    @Override
    public boolean isTokenValid(String token) {
        return Try.of(() -> extractData(this.getServletContext(), token)).isSuccess();
    }

    @Override
    public ClientConfig getClientConfig() {
        try {
            Credentials credentials;

            if (SharedPermissions.isRunningInLambda()) {
                // Running in Lambda, get session token
                credentials = Credentials.builder()
                        .accessKeyId(System.getenv("AWS_ACCESS_KEY_ID"))
                        .secretAccessKey(System.getenv("AWS_SECRET_ACCESS_KEY"))
                        .sessionToken(System.getenv("AWS_SESSION_TOKEN"))
                        .build();
            } else {
                // Running locally, get session token
                credentials = stsClient.getSessionToken().credentials();
            }

            DescribeEndpointRequest describeEndpointRequest = DescribeEndpointRequest.builder()
                    .endpointType("iot:Data-ATS")
                    .build();
            DescribeEndpointResponse describeEndpointResponse = IotClient.create().describeEndpoint(describeEndpointRequest);

            ClientConfig clientConfig = new ClientConfig();
            clientConfig.accessKeyId = credentials.accessKeyId();
            clientConfig.secretAccessKey = credentials.secretAccessKey();
            clientConfig.sessionToken = credentials.sessionToken();
            clientConfig.endpointAddress = describeEndpointResponse.endpointAddress();
            clientConfig.region = DefaultAwsRegionProviderChain.builder().build().getRegion().toString();
            clientConfig.clientId = UUID.randomUUID().toString();

            return clientConfig;
        } catch (Exception e) {
            log.info("e: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getAuthorizerName() {
        Optional<String> optionalAuthorizer = Optional.ofNullable(System.getenv(AUTHORIZERS));

        if (!optionalAuthorizer.isPresent()) {
            throw new RuntimeException("No authorizer found");
        }

        String authorizer = optionalAuthorizer.get();

        if (authorizer.contains(",")) {
            throw new RuntimeException("This architecture only expects one authorizer, cannot continue");
        }

        return authorizer;
    }

    private IotDataPlaneClient getClient() {
        if (!optionalIotDataPlaneClient.isPresent()) {
            optionalIotDataPlaneClient = Optional.of(IotDataPlaneClient.builder()
                    .endpointOverride(URI.create("https://" + endpoint))
                    .build());
        }

        return optionalIotDataPlaneClient.get();
    }

    @Override
    public List<IamPermission> getPermissions() {
        return Arrays.asList(
                IotActions.publish(IotResources.topic(String.join(DELIMITER, topicPrefix, SharedPermissions.ALL_RESOURCES))),
                IotActions.subscribe(IotResources.topicFilter(String.join(DELIMITER, topicPrefix, SharedPermissions.ALL_RESOURCES))),
                IotActions.receive(IotResources.topic(String.join(DELIMITER, topicPrefix, SharedPermissions.ALL_RESOURCES))),
                IotActions.connect(IotResources.clientId(SharedPermissions.ALL_RESOURCES)),
                IotActions.describeEndpoint);
    }
}