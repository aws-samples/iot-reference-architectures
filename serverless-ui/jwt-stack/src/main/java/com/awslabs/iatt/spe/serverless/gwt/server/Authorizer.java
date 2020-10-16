package com.awslabs.iatt.spe.serverless.gwt.server;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.aws.samples.cdk.annotations.CdkAutoWire;
import com.aws.samples.cdk.constructs.iam.permissions.HasIamPermissions;
import com.aws.samples.cdk.constructs.iam.permissions.IamPermission;
import com.aws.samples.cdk.constructs.iam.permissions.iot.IotActions;
import com.aws.samples.cdk.constructs.iam.permissions.iot.IotResources;
import com.aws.samples.cdk.constructs.iam.permissions.sts.actions.GetCallerIdentity;
import com.aws.samples.cdk.constructs.iot.authorizer.IotCustomAuthorizer;
import com.aws.samples.cdk.constructs.iot.authorizer.data.input.AuthorizationRequest;
import com.aws.samples.cdk.constructs.iot.authorizer.data.output.AuthorizationResponse;
import com.aws.samples.cdk.constructs.iot.authorizer.data.output.PolicyDocument;
import com.aws.samples.cdk.constructs.iot.authorizer.data.output.Statement;
import io.vavr.control.Try;
import org.jetbrains.annotations.NotNull;

import javax.servlet.ServletContext;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static com.awslabs.iatt.spe.serverless.gwt.client.SharedWithServer.topicPrefix;

@CdkAutoWire
public class Authorizer implements IotCustomAuthorizer, HasIamPermissions {
    public static final String APN = "APN";
    private static final TlsHelper tlsHelper = new BasicTlsHelper();
    private static Optional<KeyPair> optionalFixedKeypair = Optional.empty();

    @Override
    public AuthorizationResponse handleRequest(AuthorizationRequest authorizationRequest, Context context) {
        // Rethrow all exceptions. Inner handle function reduces try/catch nesting for readability.
        return Try.of(() -> innerHandleRequest(authorizationRequest, context)).get();
    }

    private AuthorizationResponse innerHandleRequest(AuthorizationRequest authorizationRequest, Context context) {
        LambdaLogger log = context.getLogger();

        Optional<String> optionalToken = Optional.ofNullable(authorizationRequest)
                // Get the protocol data, if available
                .map(a -> a.protocolData)
                // Get the MQTT data, if available
                .map(a -> a.mqtt)
                // Get the MQTT username, if available
                .map(a -> a.username)
                // If we get a username make sure we trim everything after the question mark
                .map(username -> username.replaceAll("\\?.*$", ""));

        if (!optionalToken.isPresent()) {
            // No token present. Cannot authenticate.
            log.log("No token present");
            return null;
        }

        String token = optionalToken.get();

        DecodedJWT decodedJWT = extractData(null, token);
        Claim iccidClaim = decodedJWT.getClaim("iccid");

        if (iccidClaim.isNull()) {
            // No ICCID found
            log.log("No ICCID found in claims");
            return null;
        }

        String iccid = iccidClaim.asString();
        String clientId = iccid;

        String allowedTopic = String.join("/", topicPrefix, clientId);

        List<Statement> statement = new ArrayList<>();
        statement.add(Statement.allowIamAction(IotActions.publish(IotResources.topic(allowedTopic))));
        statement.add(Statement.allowIamAction(IotActions.connect(IotResources.clientId(clientId))));
        statement.add(Statement.allowIamAction(IotActions.subscribe(IotResources.topicFilter(allowedTopic))));
        statement.add(Statement.allowIamAction(IotActions.receive(IotResources.topic(allowedTopic))));

        List<PolicyDocument> policyDocuments = new ArrayList<>();
        PolicyDocument policyDocument = new PolicyDocument();
        policyDocument.Version = "2012-10-17";
        policyDocument.Statement = statement;
        policyDocuments.add(policyDocument);

        AuthorizationResponse authorizationResponse = new AuthorizationResponse();
        authorizationResponse.isAuthenticated = true;
        authorizationResponse.principalId = clientId;
        authorizationResponse.disconnectAfterInSeconds = 86400;
        authorizationResponse.refreshAfterInSeconds = 300;
        authorizationResponse.policyDocuments = policyDocuments;

        return authorizationResponse;
    }

    public static DecodedJWT extractData(ServletContext servletContext, String token) {
        Algorithm algorithm = getTokenVerifier(servletContext);

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(APN)
                .build();

        return verifier.verify(token);
    }

    @NotNull
    private static Algorithm getTokenVerifier(ServletContext servletContext) {
        RSAPublicKey publicKey = getRSAPublicKey(servletContext);

        return Algorithm.RSA256(publicKey, null);
    }

    public static KeyPair getFixedKeypair(ServletContext servletContext) {
        if (!optionalFixedKeypair.isPresent()) {
            optionalFixedKeypair = Optional.of(tlsHelper.getFixedKeypair(servletContext));
        }

        return optionalFixedKeypair.get();
    }

    public static RSAPublicKey getRSAPublicKey(ServletContext servletContext) {
        return (RSAPublicKey) getFixedKeypair(servletContext).getPublic();
    }

    public static RSAPrivateKey getRSAPrivateKey(ServletContext servletContext) {
        return (RSAPrivateKey) getFixedKeypair(servletContext).getPrivate();
    }

    @Override
    public List<IamPermission> getPermissions() {
        return Collections.singletonList(new GetCallerIdentity());
    }
}