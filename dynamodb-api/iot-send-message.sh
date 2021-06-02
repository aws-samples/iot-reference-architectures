#!/usr/bin/env bash

UUID=$1
RECIPIENT_UUID=$2
PAYLOAD=$3

if [ -z "$UUID" ]; then
  echo You must specify a UUID
  exit 1
fi

if [ -z "$RECIPIENT_UUID" ]; then
  echo You must specify a recipient UUID
  exit 1
fi

if [ -z "$PAYLOAD" ]; then
  echo You must specify a payload
  exit 1
fi

TOKEN=`uuidgen`
HEX_PAYLOAD=$(echo -n $PAYLOAD | xxd -pi)
aws iot-data publish --topic request/send/$UUID/$RECIPIENT_UUID --cli-binary-format raw-in-base64-out --payload '{"token":"'$TOKEN'","hex_payload":"'$HEX_PAYLOAD'"}'
