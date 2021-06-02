package com.awssamples.iot.dynamodb.api.handlers;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.awssamples.iot.dynamodb.api.SharedHelper;
import com.awssamples.iot.dynamodb.api.data.DynamoDBMessage;
import com.awssamples.iot.dynamodb.api.data.UuidAndMessageId;
import io.vavr.collection.HashMap;
import io.vavr.control.Try;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.iotdataplane.model.PublishRequest;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.DeleteMessageRequest;
import software.amazon.awssdk.services.sqs.model.GetQueueUrlRequest;
import software.amazon.awssdk.services.sqs.model.GetQueueUrlResponse;

import java.util.List;
import java.util.Map;

import static com.awssamples.iot.dynamodb.api.SharedHelper.*;

public class HandleSqsEvent implements RequestHandler<Map, String> {
    private static final Logger log = LoggerFactory.getLogger(HandleSqsEvent.class);
    private static final String RECORDS = "Records";
    private static final String ONLY_ONE_RECORD_MAY_BE_PROCESSED_AT_A_TIME = "Only one record may be processed at a time";
    private boolean customProcessingRequired = false;

    @Override
    public String handleRequest(final Map input, final Context context) {
        List<Map> rawRecords = (List<Map>) input.get(RECORDS);

        if (rawRecords.size() != 1) {
            // Only accept one record at a time
            throw new RuntimeException(ONLY_ONE_RECORD_MAY_BE_PROCESSED_AT_A_TIME);
        }

        // We know we have exactly one record, retrieve it
        Map rawRecord = rawRecords.get(0);

        // Get the SQS specific data from the message
        String receiptHandle = (String) rawRecord.get("receiptHandle");
        String sqsMessageId = (String) rawRecord.get(MESSAGE_ID_DYNAMO_DB_COLUMN_NAME);

        // Get the SQS specific attributes from the message and then extract the sent timestamp
        Map attributes = (Map) rawRecord.get("attributes");
        String sentTimestamp = (String) attributes.get("SentTimestamp");

        // Get the map of the values from the body field which is JSON
        Map map = SharedHelper.fromJson((String) rawRecord.get(SharedHelper.BODY), Map.class);

        // Convert the map to a DynamoDB attribute value so it can be stored
        AttributeValue body = SharedHelper.toDynamoDbAttributeValue(map);

        // Create a "DynamoDB message" that has all the fields we want to store
        DynamoDBMessage dynamoDBMessage = new DynamoDBMessage(sentTimestamp, body, sqsMessageId);

        if (customProcessingRequired) {
            // If the custom processing fails the message will be returned unmodified
            dynamoDBMessage = attemptCustomProcessing(dynamoDBMessage);
        }

        // Store the message in DynamoDB
        UuidAndMessageId uuidAndMessageId = addMessageToDynamoDb(dynamoDBMessage);

        // Remove the message from SQS once it is stored in DynamoDB
        removeFromSqs(receiptHandle);

        // Publish notification to IoT Core
        publishNotification(uuidAndMessageId);

        return "done";
    }

    private DynamoDBMessage attemptCustomProcessing(DynamoDBMessage dynamoDBMessage) {
        // No custom processing implemented at the moment
        return dynamoDBMessage;
    }

    private void publishNotification(UuidAndMessageId uuidAndMessageId) {
        PublishRequest publishRequest = PublishRequest.builder()
                .topic(String.join("/", "notification", uuidAndMessageId.getUuid()))
                .qos(1)
                .payload(SdkBytes.fromByteArray(toJson(uuidAndMessageId).getBytes()))
                .build();

        // Publish with the IoT data plane client
        IOT_DATA_PLANE_CLIENT.get().publish(publishRequest);
    }


    private void removeFromSqs(String receiptHandle) {
        SqsClient sqsClient = SqsClient.create();

        GetQueueUrlRequest getQueueUrlRequest = GetQueueUrlRequest.builder()
                .queueName(SharedHelper.getInboundQueueName())
                .build();

        GetQueueUrlResponse getQueueUrlResponse = sqsClient.getQueueUrl(getQueueUrlRequest);

        // Get the queue URL from the queue name
        String queueUrl = getQueueUrlResponse.queueUrl();

        DeleteMessageRequest deleteMessageRequest = DeleteMessageRequest.builder()
                .queueUrl(queueUrl)
                .receiptHandle(receiptHandle)
                .build();

        // Delete the message from the queue
        sqsClient.deleteMessage(deleteMessageRequest);
    }

    private UuidAndMessageId addMessageToDynamoDb(DynamoDBMessage dynamoDBMessage) {
        Map<String, AttributeValue> body = dynamoDBMessage.getBody().m();

        // The message ID in DynamoDB is the user specified message ID field, followed by the SQS sent timestamp, followed by the SQS message ID (UUID)
        AttributeValue messageId = Try.of(() -> getField(MESSAGE_ID_KEY, body))
                // Add some additional data to make sure it is unique
                .map(value -> String.join("-", value, dynamoDBMessage.getSentTimestamp(), dynamoDBMessage.getSqsMessageId()))
                // If the string starts with "null-" remove it
                .map(value -> value.replaceFirst("null-", ""))
                // Turn it into an attribute value
                .map(value -> AttributeValue.builder().s(value).build())
                .onFailure(NullPointerException.class, exception -> rethrowRuntimeExceptionForMissingMessageId())
                .get();

        AttributeValue uuid = Try.of(() -> getField(UUID_KEY, body))
                // Turn it into an attribute value
                .map(value -> AttributeValue.builder().s(value).build())
                .onFailure(NullPointerException.class, exception -> rethrowRuntimeExceptionForMissingUUID())
                .get();

        HashMap<String, AttributeValue> item = HashMap.of(
                UUID_DYNAMO_DB_COLUMN_NAME, uuid,
                MESSAGE_ID_DYNAMO_DB_COLUMN_NAME, messageId,
                BODY, dynamoDBMessage.getBody());

        PutItemRequest putItemRequest = PutItemRequest.builder()
                .item(item.toJavaMap())
                .tableName(SharedHelper.getTableName())
                .build();

        DynamoDbClient.create().putItem(putItemRequest);

        return new UuidAndMessageId(uuid.s(), messageId.s());
    }

    private String getField(String fieldName, Map<String, AttributeValue> body) {
        String[] fields = fieldName.split("\\.");

        if (fields.length == 1) {
            // Not a nested field, just return the string value
            return body.get(fieldName).s();
        }

        Map<String, AttributeValue> currentMap = body;

        // Nested field. Loop through them until the last one.
        for (int loop = 0; loop < fields.length - 1; loop++) {
            currentMap = currentMap.get(fields[loop]).m();
        }

        // Last field, extract the string
        return currentMap.get(fields[fields.length - 1]).s();
    }

    private void rethrowRuntimeExceptionForMissingUUID() {
        throw new RuntimeException("UUID field [" + UUID_KEY + "] does not exist in payload");
    }

    private void rethrowRuntimeExceptionForMissingMessageId() {
        throw new RuntimeException("Message key ID field [" + MESSAGE_ID_KEY + "] does not exist in payload");
    }
}
