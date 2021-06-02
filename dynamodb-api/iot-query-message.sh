#!/usr/bin/env bash

UUID=$1

if [ -z "$UUID" ]; then
  echo You must specify a UUID
  exit 1
fi

TOKEN=`uuidgen`
aws iot-data publish --topic request/query/$UUID --cli-binary-format raw-in-base64-out --payload '{"token":"'$TOKEN'"}'
