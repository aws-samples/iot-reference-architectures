#!/usr/bin/env bash

set -e

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)

UUID_NAME=data.mo_header.imei \
MESSAGE_ID_NAME=data.mo_header.cdr_reference \
INBOUND_SQS_QUEUE_ARN=arn:aws:sqs:$REGION:$ACCOUNT_ID:ICCMO.fifo \
OUTBOUND_SQS_QUEUE_ARN=arn:aws:sqs:$REGION:$ACCOUNT_ID:ICCMT.fifo \
  time cdk deploy sqs-to-iot-core-stack
