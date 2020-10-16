package com.awssamples.sqs_to_iot_core;

import com.aws.samples.cdk.constructs.iam.permissions.SharedPermissions;
import com.aws.samples.cdk.constructs.iam.policies.LambdaPolicies;
import com.aws.samples.cdk.helpers.CdkHelper;
import com.awssamples.stacktypes.JavaGradleStack;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awscdk.core.Construct;
import software.amazon.awscdk.core.Duration;
import software.amazon.awscdk.core.RemovalPolicy;
import software.amazon.awscdk.services.dynamodb.*;
import software.amazon.awscdk.services.iam.*;
import software.amazon.awscdk.services.iot.CfnTopicRule;
import software.amazon.awscdk.services.lambda.Runtime;
import software.amazon.awscdk.services.lambda.*;
import software.amazon.awscdk.services.sqs.Queue;
import software.amazon.awscdk.services.sqs.QueueProps;

import java.util.*;

import static com.aws.samples.cdk.constructs.iam.policies.CloudWatchLogsPolicies.minimalCloudWatchEventsLoggingPolicy;
import static com.aws.samples.cdk.constructs.iam.policies.IotPolicies.searchIndexPolicyStatement;
import static com.aws.samples.cdk.helpers.CdkHelper.NO_SEPARATOR;
import static com.aws.samples.cdk.helpers.IotHelper.*;
import static com.aws.samples.cdk.helpers.ReflectionHelper.HANDLE_REQUEST;
import static com.aws.samples.cdk.helpers.RoleHelper.buildRoleAssumedByLambda;
import static com.aws.samples.cdk.helpers.RoleHelper.combinePolicyStatements;
import static com.aws.samples.cdk.helpers.RulesEngineSqlHelper.buildIotEventRule;
import static java.util.Collections.singletonList;

public class SqsToIotCoreStack extends software.amazon.awscdk.core.Stack implements JavaGradleStack {
    public static final String AWS_IOT_SQL_VERSION = "2016-03-23";
    public static final Logger log = LoggerFactory.getLogger(SqsToIotCoreStack.class);
    public static final String INBOUND_SQS_QUEUE_ARN_ENVIRONMENT_VARIABLE = "INBOUND_SQS_QUEUE_ARN";
    public static final String OUTBOUND_SQS_QUEUE_ARN_ENVIRONMENT_VARIABLE = "OUTBOUND_SQS_QUEUE_ARN";
    public static final String UUID_KEY_ENVIRONMENT_VARIABLE = "UUID_KEY";
    public static final String MESSAGE_ID_KEY_ENVIRONMENT_VARIABLE = "MESSAGE_ID_KEY";
    public static final String DYNAMO_DB_TABLE_ARN = "dynamoDbTableArn";
    public static final String INBOUND_SQS_QUEUE_ARN = "inboundSqsQueueArn";
    public static final String OUTBOUND_SQS_QUEUE_ARN = "outboundSqsQueueArn";
    public static final String UUID_KEY = "uuidKey";
    public static final String MESSAGE_ID_KEY = "messageIdKey";
    public static final String MESSAGE_ID_DYNAMO_DB_COLUMN_NAME = "messageId";
    public static final String UUID_DYNAMO_DB_COLUMN_NAME = "uuid";
    public static final String HANDLER_PACKAGE = "com.awssamples.iot.dynamodb.api.handlers";
    public static final String SQS_EVENT_HANDLER = String.join(".", HANDLER_PACKAGE, "HandleSqsEvent");
    public static final String REQUEST = "request";
    public static final String RESPONSE = "response";
    public static final String LAMBDA_INVOCATION_PERMISSIONS_PREFIX = "LambdaInvocationPermissions";
    public static final String MQTT_TOPIC_SEPARATOR = "/";
    public static final String MESSAGE_ROLE = "MessageRole";
    public static final String MESSAGE_FUNCTION = "MessageFunction";
    public static final String MESSAGE_RULE = "MessageRule";

    // GET
    public static final String GET_METHOD_NAME = String.join(".", HANDLER_PACKAGE, "HandleIotGetEvent");
    public static final String GET = "get";
    public static final String GET_REQUEST_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, REQUEST, GET);
    public static final String GET_RESPONSE_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, RESPONSE, GET);
    public static final String GET_ROLE_NAME = String.join(NO_SEPARATOR, GET, MESSAGE_ROLE);
    public static final String GET_LAMBDA_FUNCTION_NAME = String.join(NO_SEPARATOR, GET, MESSAGE_FUNCTION);
    public static final String GET_RULE_NAME = String.join(NO_SEPARATOR, GET, MESSAGE_RULE);
    public static final String GET_LAMBDA_PERMISSIONS = String.join(NO_SEPARATOR, LAMBDA_INVOCATION_PERMISSIONS_PREFIX, GET);

    // QUERY
    public static final String QUERY_METHOD_NAME = String.join(".", HANDLER_PACKAGE, "HandleIotQueryEvent");
    public static final String QUERY = "query";
    public static final String QUERY_REQUEST_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, REQUEST, QUERY);
    public static final String QUERY_RESPONSE_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, RESPONSE, QUERY);
    public static final String QUERY_ROLE_NAME = String.join(NO_SEPARATOR, QUERY, MESSAGE_ROLE);
    public static final String QUERY_LAMBDA_FUNCTION_NAME = String.join(NO_SEPARATOR, QUERY, MESSAGE_FUNCTION);
    public static final String QUERY_RULE_NAME = String.join(NO_SEPARATOR, QUERY, MESSAGE_RULE);
    public static final String QUERY_LAMBDA_PERMISSIONS = String.join(NO_SEPARATOR, LAMBDA_INVOCATION_PERMISSIONS_PREFIX, QUERY);

    // DELETE
    public static final String DELETE_METHOD_NAME = String.join(".", HANDLER_PACKAGE, "HandleIotDeleteEvent");
    public static final String DELETE = "delete";
    public static final String DELETE_REQUEST_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, REQUEST, DELETE);
    public static final String DELETE_RESPONSE_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, RESPONSE, DELETE);
    public static final String DELETE_ROLE_NAME = String.join(NO_SEPARATOR, DELETE, MESSAGE_ROLE);
    public static final String DELETE_LAMBDA_FUNCTION_NAME = String.join(NO_SEPARATOR, DELETE, MESSAGE_FUNCTION);
    public static final String DELETE_RULE_NAME = String.join(NO_SEPARATOR, DELETE, MESSAGE_RULE);
    public static final String DELETE_LAMBDA_PERMISSIONS = String.join(NO_SEPARATOR, LAMBDA_INVOCATION_PERMISSIONS_PREFIX, DELETE);

    // NEXT
    public static final String NEXT_METHOD_NAME = String.join(".", HANDLER_PACKAGE, "HandleIotNextEvent");
    public static final String NEXT = "next";
    public static final String NEXT_REQUEST_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, REQUEST, NEXT);
    public static final String NEXT_RESPONSE_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, RESPONSE, NEXT);
    public static final String NEXT_ROLE_NAME = String.join(NO_SEPARATOR, NEXT, MESSAGE_ROLE);
    public static final String NEXT_LAMBDA_FUNCTION_NAME = String.join(NO_SEPARATOR, NEXT, MESSAGE_FUNCTION);
    public static final String NEXT_RULE_NAME = String.join(NO_SEPARATOR, NEXT, MESSAGE_RULE);
    public static final String NEXT_LAMBDA_PERMISSIONS = String.join(NO_SEPARATOR, LAMBDA_INVOCATION_PERMISSIONS_PREFIX, NEXT);

    // DEVICES
    // Decide to use the registry or Dynamo DB here
    public static final String DEVICES_DYNAMODB_METHOD_NAME = String.join(".", HANDLER_PACKAGE, "HandleIotDevicesDynamoDbEvent");
    public static final String DEVICES_REGISTRY_METHOD_NAME = String.join(".", HANDLER_PACKAGE, "HandleIotDevicesRegistryEvent");
    public static final String DEVICES = "devices";
    public static final String DEVICES_REQUEST_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, REQUEST, DEVICES);
    public static final String DEVICES_RESPONSE_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, RESPONSE, DEVICES);
    public static final String DEVICES_ROLE_NAME = String.join(NO_SEPARATOR, DEVICES, MESSAGE_ROLE);
    public static final String DEVICES_LAMBDA_FUNCTION_NAME = String.join(NO_SEPARATOR, DEVICES, MESSAGE_FUNCTION);
    public static final String DEVICES_RULE_NAME = String.join(NO_SEPARATOR, DEVICES, MESSAGE_RULE);
    public static final String DEVICES_LAMBDA_PERMISSIONS = String.join(NO_SEPARATOR, LAMBDA_INVOCATION_PERMISSIONS_PREFIX, DEVICES);

    // SEND
    public static final String SEND_METHOD_NAME = String.join(".", HANDLER_PACKAGE, "HandleIotSendEvent");
    public static final String SEND = "send";
    public static final String SEND_REQUEST_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, REQUEST, SEND);
    public static final String SEND_RESPONSE_TOPIC_PREFIX = String.join(MQTT_TOPIC_SEPARATOR, RESPONSE, SEND);
    public static final String SEND_ROLE_NAME = String.join(NO_SEPARATOR, SEND, MESSAGE_ROLE);
    public static final String SEND_LAMBDA_FUNCTION_NAME = String.join(NO_SEPARATOR, SEND, MESSAGE_FUNCTION);
    public static final String SEND_RULE_NAME = String.join(NO_SEPARATOR, SEND, MESSAGE_RULE);
    public static final String SEND_LAMBDA_PERMISSIONS = String.join(NO_SEPARATOR, LAMBDA_INVOCATION_PERMISSIONS_PREFIX, SEND);

    // NOTIFICATION
    public static final String NOTIFICATION_METHOD_NAME = String.join(".", HANDLER_PACKAGE, "HandleIotNotificationEvent");
    public static final String NOTIFICATION = "notification";
    public static final String NOTIFICATION_TOPIC_FILTER = String.join(MQTT_TOPIC_SEPARATOR, NOTIFICATION, "+");
    public static final String NOTIFICATION_ROLE_NAME = String.join(NO_SEPARATOR, NOTIFICATION, MESSAGE_ROLE);
    public static final String NOTIFICATION_LAMBDA_FUNCTION_NAME = String.join(NO_SEPARATOR, NOTIFICATION, MESSAGE_FUNCTION);
    public static final String NOTIFICATION_RULE_NAME = String.join(NO_SEPARATOR, NOTIFICATION, MESSAGE_RULE);
    public static final String NOTIFICATION_LAMBDA_PERMISSIONS = String.join(NO_SEPARATOR, LAMBDA_INVOCATION_PERMISSIONS_PREFIX, NOTIFICATION);

    public static final String DEFAULT_UUID_KEY = "thingName";
    public static final String DEFAULT_MESSAGE_ID_KEY = "epochTime";
    public static final String MULTI_LEVEL_MQTT_WILDCARD = "#";
    public static final String REQUEST_TOPIC_PREFIX_KEY = "RequestTopicPrefix";
    public static final String RESPONSE_TOPIC_PREFIX_KEY = "ResponseTopicPrefix";
    public static final String DEFAULT_SELECT_CLAUSE = "select *, topic() as topic";
    public final String projectDirectory = "../dynamodb-api/java/";
    public final String outputJarName = "java-1.0-SNAPSHOT-all.jar";
    public final Duration queueVisibilityTimeout = Duration.seconds(30);
    // Queue visibility timeout must be greater than Lambda timeout
    public final Duration lambdaFunctionTimeout = Duration.seconds((int) queueVisibilityTimeout.toSeconds() / 2);
    // Whether to use DynamoDB or the IoT registry for device lookup
    private final boolean dynamoDbDeviceLookup = false;

    public SqsToIotCoreStack(final Construct parent, final String name) {
        super(parent, name);

        // Build all of the necessary JARs
        build();

        Optional<Map<String, String>> optionalArguments = CdkHelper.getArguments();

        // Get the queue ARN from the arguments or build the message queue and extract the ARN
        String inboundSqsQueueArn = optionalArguments
                .flatMap(this::getInboundQueueArn)
                .orElseGet(() -> buildInboundMessageQueue().getQueueArn());

        String outboundSqsQueueArn = optionalArguments
                .flatMap(this::getOutboundQueueArn)
                .orElseGet(() -> buildOutboundMessageQueue().getQueueArn());

        Table messageTable = buildMessageTable();

        String uuidKey = optionalArguments
                .flatMap(this::getUuid)
                .orElseGet(this::getDefaultUuidKeyAndWarn);

        String messageIdKey = optionalArguments
                .flatMap(this::getMessageId)
                .orElseGet(this::getDefaultMessageKeyIdAndWarn);

        // Resources to move messages from SQS to DynamoDB
        Role moveFromSqsToDynamoDbRole = buildMoveFromSqsToDynamoDbRole(inboundSqsQueueArn, messageTable);
        Function moveFromSqsToDynamoDb = buildMoveFromSqsToDynamoDbLambda(inboundSqsQueueArn, uuidKey, messageIdKey, messageTable, moveFromSqsToDynamoDbRole);
        buildEventSourceMapping(inboundSqsQueueArn, moveFromSqsToDynamoDb);

        // Default environment for all functions just contains the table name
        Map<String, String> defaultEnvironment = getDefaultEnvironment(messageTable);

        // Resources to get messages from DynamoDB and publish to IoT Core
        List<PolicyStatement> getItemPolicyStatementsForMessageTable = singletonList(getGetItemPolicyStatementForTable(messageTable));
        Role getRole = buildIotEventRoleForTopicPrefix(GET_ROLE_NAME, GET_RESPONSE_TOPIC_PREFIX, Optional.of(getItemPolicyStatementsForMessageTable), Optional.empty());
        String getRequestTopicFilter = String.join(MQTT_TOPIC_SEPARATOR, GET_REQUEST_TOPIC_PREFIX, MULTI_LEVEL_MQTT_WILDCARD);
        Map<String, String> getMessageLambdaEnvironment = getGetMessageLambdaEnvironment();
        Function getLambda = buildIotEventLambda(GET_LAMBDA_FUNCTION_NAME, getRole, defaultEnvironment, getMessageLambdaEnvironment, GET_METHOD_NAME);
        CfnTopicRule getRule = buildIotEventRule(this, GET_RULE_NAME, getLambda, DEFAULT_SELECT_CLAUSE, getRequestTopicFilter);
        allowIotTopicRuleToInvokeLambdaFunction(this, getRule, getLambda, GET_LAMBDA_PERMISSIONS);

        // Resources to query for available messages from DynamoDB and publish to IoT Core
        List<PolicyStatement> queryPolicyStatementsForMessageTable = singletonList(getQueryPolicyStatementForTable(messageTable));
        Role queryRole = buildIotEventRoleForTopicPrefix(QUERY_ROLE_NAME, QUERY_RESPONSE_TOPIC_PREFIX, Optional.of(queryPolicyStatementsForMessageTable), Optional.empty());
        String queryRequestTopicFilter = String.join(MQTT_TOPIC_SEPARATOR, QUERY_REQUEST_TOPIC_PREFIX, MULTI_LEVEL_MQTT_WILDCARD);
        Map<String, String> queryMessageLambdaEnvironment = getQueryMessageLambdaEnvironment();
        Function queryLambda = buildIotEventLambda(QUERY_LAMBDA_FUNCTION_NAME, queryRole, defaultEnvironment, queryMessageLambdaEnvironment, QUERY_METHOD_NAME);
        CfnTopicRule queryRule = buildIotEventRule(this, QUERY_RULE_NAME, queryLambda, DEFAULT_SELECT_CLAUSE, queryRequestTopicFilter);
        allowIotTopicRuleToInvokeLambdaFunction(this, queryRule, queryLambda, QUERY_LAMBDA_PERMISSIONS);

        // Resources to delete messages from DynamoD0
        List<PolicyStatement> deleteItemPolicyStatementsForMessageTable = singletonList(getDeleteItemPolicyStatementForTable(messageTable));
        Role deleteRole = buildIotEventRoleForTopicPrefix(DELETE_ROLE_NAME, DELETE_RESPONSE_TOPIC_PREFIX, Optional.of(deleteItemPolicyStatementsForMessageTable), Optional.empty());
        String deleteRequestTopicFilter = String.join(MQTT_TOPIC_SEPARATOR, DELETE_REQUEST_TOPIC_PREFIX, MULTI_LEVEL_MQTT_WILDCARD);
        Map<String, String> deleteMessageLambdaEnvironment = getDeleteMessageLambdaEnvironment();
        Function deleteLambda = buildIotEventLambda(DELETE_LAMBDA_FUNCTION_NAME, deleteRole, defaultEnvironment, deleteMessageLambdaEnvironment, DELETE_METHOD_NAME);
        CfnTopicRule deleteRule = buildIotEventRule(this, DELETE_RULE_NAME, deleteLambda, DEFAULT_SELECT_CLAUSE, deleteRequestTopicFilter);
        allowIotTopicRuleToInvokeLambdaFunction(this, deleteRule, deleteLambda, DELETE_LAMBDA_PERMISSIONS);

        // Resources to get the next message ID from DynamoDB
        List<PolicyStatement> nextItemPolicyStatementsForMessageTable = singletonList(getNextItemPolicyStatementForTable(messageTable));
        Role nextRole = buildIotEventRoleForTopicPrefix(NEXT_ROLE_NAME, NEXT_RESPONSE_TOPIC_PREFIX, Optional.of(nextItemPolicyStatementsForMessageTable), Optional.empty());
        String nextRequestTopicFilter = String.join(MQTT_TOPIC_SEPARATOR, NEXT_REQUEST_TOPIC_PREFIX, MULTI_LEVEL_MQTT_WILDCARD);
        Map<String, String> nextMessageLambdaEnvironment = getNextMessageLambdaEnvironment();
        Function nextLambda = buildIotEventLambda(NEXT_LAMBDA_FUNCTION_NAME, nextRole, defaultEnvironment, nextMessageLambdaEnvironment, NEXT_METHOD_NAME);
        CfnTopicRule nextRule = buildIotEventRule(this, NEXT_RULE_NAME, nextLambda, DEFAULT_SELECT_CLAUSE, nextRequestTopicFilter);
        allowIotTopicRuleToInvokeLambdaFunction(this, nextRule, nextLambda, NEXT_LAMBDA_PERMISSIONS);

        // Resources to get the list of devices with unread messages from DynamoDB
        String devicesRequestTopicFilter = String.join(MQTT_TOPIC_SEPARATOR, DEVICES_REQUEST_TOPIC_PREFIX, MULTI_LEVEL_MQTT_WILDCARD);
        Map<String, String> devicesMessageLambdaEnvironment = getDevicesMessageLambdaEnvironment();
        Function devicesLambda;

        if (dynamoDbDeviceLookup) {
            List<PolicyStatement> devicesDynamoDbPolicyStatementsForMessageTable = singletonList(getDevicesPolicyStatementForTable(messageTable));
            Role dynamoDbDevicesRole = buildIotEventRoleForTopicPrefix(DEVICES_ROLE_NAME, DEVICES_RESPONSE_TOPIC_PREFIX, Optional.of(devicesDynamoDbPolicyStatementsForMessageTable), Optional.empty());
            Function dynamoDbDevicesLambda = buildIotEventLambda(DEVICES_LAMBDA_FUNCTION_NAME, dynamoDbDevicesRole, defaultEnvironment, devicesMessageLambdaEnvironment, DEVICES_DYNAMODB_METHOD_NAME);
            devicesLambda = dynamoDbDevicesLambda;
        } else {
            List<PolicyStatement> devicesRegistryPolicyStatements = singletonList(searchIndexPolicyStatement);
            Role registryDevicesRole = buildIotEventRoleForTopicPrefix(DEVICES_ROLE_NAME, DEVICES_RESPONSE_TOPIC_PREFIX, Optional.of(devicesRegistryPolicyStatements), Optional.empty());
            Function registryDevicesLambda = buildIotEventLambda(DEVICES_LAMBDA_FUNCTION_NAME, registryDevicesRole, defaultEnvironment, devicesMessageLambdaEnvironment, DEVICES_REGISTRY_METHOD_NAME);
            devicesLambda = registryDevicesLambda;
        }

        CfnTopicRule devicesRule = buildIotEventRule(this, DEVICES_RULE_NAME, devicesLambda, DEFAULT_SELECT_CLAUSE, devicesRequestTopicFilter);
        allowIotTopicRuleToInvokeLambdaFunction(this, devicesRule, devicesLambda, DEVICES_LAMBDA_PERMISSIONS);

        // Resources to send messages to SQS
        List<PolicyStatement> sendToSqsPolicyStatements = singletonList(getSqsSendMessagePolicyStatement(outboundSqsQueueArn));
        Role sendRole = buildIotEventRoleForTopicPrefix(SEND_ROLE_NAME, SEND_RESPONSE_TOPIC_PREFIX, Optional.of(sendToSqsPolicyStatements), Optional.empty());
        String sendRequestTopicFilter = String.join(MQTT_TOPIC_SEPARATOR, SEND_REQUEST_TOPIC_PREFIX, MULTI_LEVEL_MQTT_WILDCARD);
        Map<String, String> sendMessageLambdaEnvironment = getSendMessageLambdaEnvironment(outboundSqsQueueArn);
        Function sendLambda = buildIotEventLambda(SEND_LAMBDA_FUNCTION_NAME, sendRole, defaultEnvironment, sendMessageLambdaEnvironment, SEND_METHOD_NAME);
        CfnTopicRule sendRule = buildIotEventRule(this, SEND_RULE_NAME, sendLambda, DEFAULT_SELECT_CLAUSE, sendRequestTopicFilter);
        allowIotTopicRuleToInvokeLambdaFunction(this, sendRule, sendLambda, SEND_LAMBDA_PERMISSIONS);

        // Resources to receive notifications and add devices to the registry
        List<PolicyStatement> notificationCreateThingPolicyStatements = Arrays.asList(createThingPolicyStatement,
                updateThingShadowPolicyStatement,
                updateThingGroupsForThingPolicyStatement,
                createThingGroupPolicyStatement);
        Role notificationRole = buildRoleAssumedByLambda(this, NOTIFICATION_ROLE_NAME, Optional.of(notificationCreateThingPolicyStatements), Optional.empty());
        Function notificationLambda = buildIotEventLambda(NOTIFICATION_LAMBDA_FUNCTION_NAME, notificationRole, defaultEnvironment, NOTIFICATION_METHOD_NAME);
        CfnTopicRule notificationRule = buildIotEventRule(this, NOTIFICATION_RULE_NAME, notificationLambda, DEFAULT_SELECT_CLAUSE, NOTIFICATION_TOPIC_FILTER);
        allowIotTopicRuleToInvokeLambdaFunction(this, notificationRule, notificationLambda, NOTIFICATION_LAMBDA_PERMISSIONS);
    }

    @NotNull
    private String getDefaultUuidKeyAndWarn() {
        log.warn("No UUID key specified, using " + DEFAULT_UUID_KEY + " as default value");
        return DEFAULT_UUID_KEY;
    }

    @NotNull
    private String getDefaultMessageKeyIdAndWarn() {
        log.warn("No message ID key specified, using " + DEFAULT_MESSAGE_ID_KEY + " as default value");
        return DEFAULT_MESSAGE_ID_KEY;
    }

    private Optional<String> getInboundQueueArn(Map<String, String> map) {
        return Optional.ofNullable(map.get(INBOUND_SQS_QUEUE_ARN_ENVIRONMENT_VARIABLE));
    }

    private Optional<String> getOutboundQueueArn(Map<String, String> map) {
        return Optional.ofNullable(map.get(OUTBOUND_SQS_QUEUE_ARN_ENVIRONMENT_VARIABLE));
    }

    private Optional<String> getUuid(Map<String, String> map) {
        return Optional.ofNullable(map.get(UUID_KEY_ENVIRONMENT_VARIABLE));
    }

    private Optional<String> getMessageId(Map<String, String> map) {
        return Optional.ofNullable(map.get(MESSAGE_ID_KEY_ENVIRONMENT_VARIABLE));
    }

    private Queue buildInboundMessageQueue() {
        log.warn("Environment variable [" + INBOUND_SQS_QUEUE_ARN_ENVIRONMENT_VARIABLE + "] not specified, using a default inbound SQS queue");

        QueueProps queueProps = QueueProps.builder()
                .visibilityTimeout(queueVisibilityTimeout)
                .build();
        return new Queue(this, "InboundSqsQueue", queueProps);
    }

    private Queue buildOutboundMessageQueue() {
        log.warn("Environment variable [" + OUTBOUND_SQS_QUEUE_ARN_ENVIRONMENT_VARIABLE + "] not specified, using a default outbound SQS queue");

        QueueProps queueProps = QueueProps.builder()
                .visibilityTimeout(queueVisibilityTimeout)
                .build();
        return new Queue(this, "OutboundSqsQueue", queueProps);
    }

    private EventSourceMapping buildEventSourceMapping(String sqsQueueArn, Function lambda) {
        EventSourceMappingProps eventSourceMappingProps = EventSourceMappingProps.builder()
                .eventSourceArn(sqsQueueArn)
                .batchSize(1)
                .target(lambda)
                .enabled(true)
                .build();

        return new EventSourceMapping(this, "MoveFromSqsToDynamoDbEventSourceMapping", eventSourceMappingProps);
    }

    private Map<String, String> getDefaultEnvironment(Table table) {
        Map<String, String> environment = new HashMap<>();
        environment.put(DYNAMO_DB_TABLE_ARN, table.getTableArn());

        return environment;
    }

    private Map<String, String> getGetMessageLambdaEnvironment() {
        Map<String, String> environment = new HashMap<>();
        environment.put(GET + REQUEST_TOPIC_PREFIX_KEY, GET_REQUEST_TOPIC_PREFIX);
        environment.put(GET + RESPONSE_TOPIC_PREFIX_KEY, GET_RESPONSE_TOPIC_PREFIX);

        return environment;
    }

    private Map<String, String> getQueryMessageLambdaEnvironment() {
        Map<String, String> environment = new HashMap<>();
        environment.put(QUERY + REQUEST_TOPIC_PREFIX_KEY, QUERY_REQUEST_TOPIC_PREFIX);
        environment.put(QUERY + RESPONSE_TOPIC_PREFIX_KEY, QUERY_RESPONSE_TOPIC_PREFIX);

        return environment;
    }

    private Map<String, String> getDeleteMessageLambdaEnvironment() {
        Map<String, String> environment = new HashMap<>();
        environment.put(DELETE + REQUEST_TOPIC_PREFIX_KEY, DELETE_REQUEST_TOPIC_PREFIX);
        environment.put(DELETE + RESPONSE_TOPIC_PREFIX_KEY, DELETE_RESPONSE_TOPIC_PREFIX);

        return environment;
    }

    private Map<String, String> getNextMessageLambdaEnvironment() {
        Map<String, String> environment = new HashMap<>();
        environment.put(NEXT + REQUEST_TOPIC_PREFIX_KEY, NEXT_REQUEST_TOPIC_PREFIX);
        environment.put(NEXT + RESPONSE_TOPIC_PREFIX_KEY, NEXT_RESPONSE_TOPIC_PREFIX);

        return environment;
    }

    private Map<String, String> getDevicesMessageLambdaEnvironment() {
        Map<String, String> environment = new HashMap<>();
        environment.put(DEVICES + REQUEST_TOPIC_PREFIX_KEY, DEVICES_REQUEST_TOPIC_PREFIX);
        environment.put(DEVICES + RESPONSE_TOPIC_PREFIX_KEY, DEVICES_RESPONSE_TOPIC_PREFIX);

        return environment;
    }

    private Map<String, String> getSendMessageLambdaEnvironment(String outboundSqsQueueArn) {
        Map<String, String> environment = new HashMap<>();
        environment.put(SEND + REQUEST_TOPIC_PREFIX_KEY, SEND_REQUEST_TOPIC_PREFIX);
        environment.put(SEND + RESPONSE_TOPIC_PREFIX_KEY, SEND_RESPONSE_TOPIC_PREFIX);
        environment.put(OUTBOUND_SQS_QUEUE_ARN, outboundSqsQueueArn);

        return environment;
    }

    private Function buildIotEventLambda(String functionName, Role role, Map<String, String> defaultEnvironment, String handlerClassName) {
        return buildIotEventLambda(functionName, role, defaultEnvironment, new HashMap<>(), handlerClassName);
    }

    private Function buildIotEventLambda(String functionName, Role role, Map<String, String> defaultEnvironment, Map<String, String> additionalEnvironment, String handlerClassName) {
        Map<String, String> environment = new HashMap<>(defaultEnvironment);
        environment.putAll(additionalEnvironment);

        FunctionProps functionProps = FunctionProps.builder()
                .code(getAssetCode())
                .handler(String.join("::", handlerClassName, HANDLE_REQUEST))
                .memorySize(1024)
                .timeout(lambdaFunctionTimeout)
                .environment(environment)
                .runtime(Runtime.JAVA_8)
                .role(role)
                .tracing(Tracing.ACTIVE)
                .build();

        return new Function(this, functionName, functionProps);
    }

    private Function buildMoveFromSqsToDynamoDbLambda(String inboundSqsQueueArn, String uuidKey, String messageIdKey, Table table, Role role) {
        Map<String, String> environment = new HashMap<>();
        environment.put(INBOUND_SQS_QUEUE_ARN, inboundSqsQueueArn);
        environment.put(DYNAMO_DB_TABLE_ARN, table.getTableArn());
        environment.put(UUID_KEY, uuidKey);
        environment.put(MESSAGE_ID_KEY, messageIdKey);

        FunctionProps functionProps = FunctionProps.builder()
                .code(getAssetCode())
                .handler(String.join("::", SQS_EVENT_HANDLER, HANDLE_REQUEST))
                .memorySize(1024)
                .timeout(lambdaFunctionTimeout)
                .environment(environment)
                .runtime(Runtime.JAVA_8)
                .role(role)
                .tracing(Tracing.ACTIVE)
                .build();

        return new Function(this, "MoveFromSqsToDynamoDbLambda", functionProps);
    }

    private Role buildMoveFromSqsToDynamoDbRole(String queueArn, Table table) {
        PolicyStatement sqsPolicyStatement = LambdaPolicies.getMinimalLambdaSqsQueueEventSourceMappingTargetPolicy(queueArn);

        PolicyStatementProps dynamoDbPolicyStatementProps = PolicyStatementProps.builder()
                .effect(Effect.ALLOW)
                .resources(singletonList(table.getTableArn()))
                .actions(singletonList(SharedPermissions.DYNAMODB_PUT_ITEM_PERMISSION))
                .build();
        PolicyStatement dynamoDbPolicyStatement = new PolicyStatement(dynamoDbPolicyStatementProps);

        PolicyStatement iotPolicyStatement = getPublishToTopicPrefixPolicyStatement(this, "notification");

        PolicyDocumentProps policyDocumentProps = PolicyDocumentProps.builder()
                .statements(Arrays.asList(sqsPolicyStatement,
                        minimalCloudWatchEventsLoggingPolicy,
                        dynamoDbPolicyStatement,
                        iotPolicyStatement))
                .build();
        PolicyDocument policyDocument = new PolicyDocument(policyDocumentProps);

        Map<String, PolicyDocument> policyDocuments = new HashMap<>();
        policyDocuments.put("root", policyDocument);

        RoleProps moveFromSqsToDynamoDbRoleProps = RoleProps.builder()
                .assumedBy(LambdaPolicies.LAMBDA_SERVICE_PRINCIPAL)
                .inlinePolicies(policyDocuments)
                .build();

        return new Role(this, "MoveFromSqsToDynamoDbRole", moveFromSqsToDynamoDbRoleProps);
    }

    private PolicyStatement getSqsSendMessagePolicyStatement(String queueArn) {
        PolicyStatementProps sqsPolicyStatementProps = PolicyStatementProps.builder()
                .effect(Effect.ALLOW)
                .resources(Collections.singletonList(queueArn))
                .actions(Arrays.asList("sqs:SendMessage", "sqs:GetQueueUrl"))
                .build();

        return new PolicyStatement(sqsPolicyStatementProps);
    }

    private Role buildIotEventRoleForTopicPrefix(String roleName, String topicPrefix, Optional<List<PolicyStatement>> optionalPolicyStatements, Optional<List<ManagedPolicy>> optionalManagedPolicies) {
        PolicyStatement iotPolicyStatement = getPublishToTopicPrefixPolicyStatement(this, topicPrefix);

        return buildRoleAssumedByLambda(this, roleName, Optional.of(combinePolicyStatements(optionalPolicyStatements, iotPolicyStatement)), optionalManagedPolicies);
    }

    private PolicyStatement getGetItemPolicyStatementForTable(Table table) {
        return getPolicyStatementForTable(table, SharedPermissions.DYNAMODB_GET_ITEM_PERMISSION);
    }

    private PolicyStatement getQueryPolicyStatementForTable(Table table) {
        return getPolicyStatementForTable(table, SharedPermissions.DYNAMODB_QUERY_PERMISSION);
    }

    private PolicyStatement getDeleteItemPolicyStatementForTable(Table table) {
        return getPolicyStatementForTable(table, SharedPermissions.DYNAMODB_DELETE_ITEM_PERMISSION);
    }

    private PolicyStatement getNextItemPolicyStatementForTable(Table table) {
        return getPolicyStatementForTable(table, SharedPermissions.DYNAMODB_QUERY_PERMISSION);
    }

    private PolicyStatement getDevicesPolicyStatementForTable(Table table) {
        return getPolicyStatementForTable(table, SharedPermissions.DYNAMODB_SCAN_PERMISSION);
    }

    private PolicyStatement getPolicyStatementForTable(Table table, String action) {
        PolicyStatementProps dynamoDbPolicyStatementProps = PolicyStatementProps.builder()
                .effect(Effect.ALLOW)
                .resources(singletonList(table.getTableArn()))
                .actions(singletonList(action))
                .build();
        return new PolicyStatement(dynamoDbPolicyStatementProps);
    }

    private Table buildMessageTable() {
        Attribute uuid = Attribute.builder()
                .type(AttributeType.STRING)
                .name(UUID_DYNAMO_DB_COLUMN_NAME)
                .build();

        Attribute messageId = Attribute.builder()
                .type(AttributeType.STRING)
                .name(MESSAGE_ID_DYNAMO_DB_COLUMN_NAME)
                .build();

        TableProps tableProps = TableProps.builder()
                .partitionKey(uuid)
                .sortKey(messageId)
                .billingMode(BillingMode.PAY_PER_REQUEST)
                .removalPolicy(RemovalPolicy.DESTROY)
                .build();

        return new Table(this, "DynamoDbTable", tableProps);
    }

    @Override
    public String getProjectDirectory() {
        return projectDirectory;
    }

    @Override
    public String getOutputArtifactName() {
        return outputJarName;
    }
}