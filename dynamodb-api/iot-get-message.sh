#!/usr/bin/env bash

UUID=$1
MESSAGE_ID=$2

if [ -z "$UUID" ]; then
  echo You must specify a UUID
  exit 1
fi

if [ -z "$MESSAGE_ID" ]; then
  echo You must specify a message ID
  exit 1
fi

TOKEN=`uuidgen`
aws iot-data publish --topic request/get/$UUID/$MESSAGE_ID --cli-binary-format raw-in-base64-out --payload '{"token":"'$TOKEN'"}'
