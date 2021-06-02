package com.awssamples.iot.dynamodb.api.handlers;

import com.awssamples.iot.dynamodb.api.SharedHelper;
import com.awssamples.iot.dynamodb.api.handlers.interfaces.HandleIotEvent;
import io.vavr.collection.HashMap;
import io.vavr.control.Option;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.GetQueueUrlRequest;
import software.amazon.awssdk.services.sqs.model.GetQueueUrlResponse;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageResponse;

import java.util.Map;
import java.util.Random;
import java.util.UUID;

import static com.awssamples.iot.dynamodb.api.SharedHelper.getGson;

public class HandleIotSendEvent implements HandleIotEvent {
    private static final Logger log = LoggerFactory.getLogger(HandleIotSendEvent.class);

    @Override
    public String getOperationType() {
        return "send";
    }

    @Override
    public String innerHandle(String responseToken, final Map input, Option<String> uuidOption, Option<String> messageIdOption, Option<String> recipientIdOption) {
        byte[] payload = getPayload(input);
        String recipientUuid = recipientIdOption.get();

        String sqsMessageId = putInSqs(recipientUuid, payload);

        // Return a payload on the response topic that contains the confirmation that the message was put in SQS
        HashMap<String, Object> payloadMap = HashMap.of(
                "sqs_message_id", sqsMessageId);

        publishResponse(uuidOption, messageIdOption, recipientIdOption, responseToken, payloadMap);

        return "done";
    }

    private String putInSqs(String uuid, byte[] payload) {
        SqsClient sqsClient = SqsClient.create();

        GetQueueUrlRequest getQueueUrlRequest = GetQueueUrlRequest.builder()
                .queueName(SharedHelper.getOutboundQueueName())
                .build();

        GetQueueUrlResponse getQueueUrlResponse = sqsClient.getQueueUrl(getQueueUrlRequest);

        // Get the queue URL from the queue name
        String queueUrl = getQueueUrlResponse.queueUrl();

        String encodedPayload = Hex.encodeHexString(payload);

        HashMap<String, Object> body = HashMap.of(
                "client_message_id", Math.abs(new Random().nextInt()),
                "message", encodedPayload,
                "imei", uuid);

        String encodedBody = getGson().toJson(body);

        SendMessageRequest.Builder sendMessageRequestBuilder = SendMessageRequest.builder()
                .queueUrl(queueUrl)
                .messageBody(encodedBody);

        if (outboundQueueIsFifoQueue()) {
            // FIFO queues need deduplication and group IDs
            sendMessageRequestBuilder
                    .messageDeduplicationId(UUID.randomUUID().toString())
                    .messageGroupId(UUID.randomUUID().toString());
        }

        // Send the message to the queue
        SendMessageResponse sendMessageResponse = sqsClient.sendMessage(sendMessageRequestBuilder.build());

        return sendMessageResponse.messageId();
    }

    private boolean outboundQueueIsFifoQueue() {
        // From https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues.html
        //   "The name of a FIFO queue must end with the .fifo suffix"
        return SharedHelper.getOutboundQueueName().endsWith(".fifo");
    }

    @Override
    public boolean isMessageIdRequired() {
        // No message ID required
        return false;
    }

    @Override
    public boolean isRecipientUuidRequired() {
        return true;
    }

    @Override
    public boolean isDeviceUuidRequired() {
        return true;
    }
}
