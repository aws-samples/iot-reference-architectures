package com.awssamples.iot.dynamodb.api.data;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

public class DynamoDBMessage {
    /**
     * The value from SQS called "SentTimestamp"
     */
    private final String sentTimestamp;

    /**
     * The original body of the message that was sent to SQS in DynamoDB AttributeValue format
     */
    private final AttributeValue body;

    /**
     * The value from SQS called "MessageID" which is a UUID
     */
    private final String sqsMessageId;

    public DynamoDBMessage(String sentTimestamp, AttributeValue body, String sqsMessageId) {
        this.sentTimestamp = sentTimestamp;
        this.body = body;
        this.sqsMessageId = sqsMessageId;
    }

    public String getSqsMessageId() {
        return sqsMessageId;
    }

    public String getSentTimestamp() {
        return sentTimestamp;
    }

    public AttributeValue getBody() {
        return body;
    }
}
