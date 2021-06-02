#!/usr/bin/env bash

QUEUE_URL=$(aws sqs list-queues --query "QueueUrls[?contains(@, 'sqs-to-iot-core-stack') == \`true\`]" --output text)

if [ -z "$QUEUE_URL" ]; then
  echo Could not find any SQS queues that were created with the SQS to IoT Core stack. This script will not purge custom queues.
  exit 1
fi

aws sqs purge-queue --queue-url "$QUEUE_URL"
