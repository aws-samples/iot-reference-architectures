#!/usr/bin/env bash

TOKEN=`uuidgen`
aws iot-data publish --topic request/devices --cli-binary-format raw-in-base64-out --payload '{"token":"'$TOKEN'"}'
