package com.awssamples.serverless_ui;

import com.aws.samples.cdk.helpers.IotHelper;
import com.aws.samples.cdk.helpers.ServerlessHelper;
import com.aws.samples.cdk.helpers.data.AwsLambdaServlet;
import com.awssamples.stacktypes.JavaGradleStack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awscdk.core.CfnOutput;
import software.amazon.awscdk.core.CfnOutputProps;
import software.amazon.awscdk.core.Construct;
import software.amazon.awscdk.services.apigateway.LambdaRestApi;
import software.amazon.awscdk.services.iot.CfnAuthorizer;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.aws.samples.cdk.helpers.ServerlessHelper.AUTHORIZERS;

public class ServerlessUiStack extends software.amazon.awscdk.core.Stack implements JavaGradleStack {
    private static final Logger log = LoggerFactory.getLogger(ServerlessUiStack.class);

    private String projectDirectory;
    private String outputArtifactName;
    private HashMap<String, String> lambdaEnvironment = new HashMap<>();
    private List<CfnAuthorizer> iotCustomAuthorizers;

    public ServerlessUiStack(final Construct parent, final String name) {
        super(parent, name);

        projectDirectory = "../serverless-ui/" + name + "/";
        outputArtifactName = name + "-all.jar";

        // Build all of the necessary JARs
        String hash = build();

        // Optional - for custom authorizer demos
        iotCustomAuthorizers = IotHelper.getIotCustomAuthorizers(this, getOutputArtifactFile(), hash);
        logCount("IoT custom authorizers", iotCustomAuthorizers);

        addAuthorizerNamesToLambdaEnvironment();

        List<AwsLambdaServlet> awsLambdaServlets = ServerlessHelper.getAwsLambdaServlets(this, getOutputArtifactFile(), Optional.of(lambdaEnvironment));
        logCount("servlets", awsLambdaServlets);

        LambdaRestApi lambdaRestApi = ServerlessHelper.buildLambdaRestApiIfPossible(this, awsLambdaServlets);

        // Include the URL for the serverless UI in the output so it's easier to find later
        CfnOutputProps url = CfnOutputProps.builder()
                .exportName(String.join("-", getStackName(), "url"))
                .value(lambdaRestApi.getUrl())
                .build();

        CfnOutput output = new CfnOutput(this, String.join("-", getStackName(), "api"), url);
    }

    private void logCount(String type, List<?> list) {
        if (list.isEmpty()) {
            log.info("No " + type + " found");
        } else {
            log.info("Number of " + type + " found: " + list.size());
        }
    }

    private void addAuthorizerNamesToLambdaEnvironment() {
        String authorizers = iotCustomAuthorizers.stream()
                .map(CfnAuthorizer::getAuthorizerName)
                .collect(Collectors.joining(","));

        if (!authorizers.isEmpty()) {
            lambdaEnvironment.put(AUTHORIZERS, authorizers);
        }
    }

    @Override
    public String getProjectDirectory() {
        return projectDirectory;
    }

    @Override
    public String getOutputArtifactName() {
        return outputArtifactName;
    }
}