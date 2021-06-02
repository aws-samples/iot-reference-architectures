#!/usr/bin/env bash

UUID=$1

if [ -z "$UUID" ]; then
  echo You must specify a UUID
  exit 1
fi

if [ -z "$QUEUE_URL" ];
then
  QUEUE_URL=$(aws sqs list-queues --query "QueueUrls[?contains(@, 'sqs-to-iot-core-stack') && contains(@, 'Inbound')]" --output text | grep Inbound)

  if [ -z "$QUEUE_URL" ];
  then
    echo QUEUE_URL not specified in the environment and could not be found in the CloudFormation stack. The queue must be created by the CloudFormation stack or its URL must be passed in as an environment variable.
    exit 1
  fi
fi
echo $QUEUE_URL

MESSAGE=$(cat sqs-example.json)
EPOCH_TIME=$(date +%s)
MESSAGE=${MESSAGE//EPOCH_TIME/$EPOCH_TIME}
MESSAGE=${MESSAGE//UUID/$UUID}
echo $MESSAGE
aws sqs send-message --queue-url "$QUEUE_URL" --message-body "$MESSAGE"
