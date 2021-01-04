#!/usr/bin/env bash

BUILD_TAG=$1
JAR=$2

if [ -z "$BUILD_TAG" ]; then
  echo >&2 "No build tag specified. This must be the first parameter to get-command.sh"
  exit 1
fi

if [ -z "$JAR" ]; then
  echo >&2 "No JAR specified. This must be the second parameter to get-command.sh"
  exit 1
fi

command -v java &>/dev/null && command -v cdk &>/dev/null

HAS_JAVA_AND_CDK=$?

if [ ${HAS_JAVA_AND_CDK} -eq 0 ]; then
  # Echo to standard error since we need to use standard out to determine which command to run by other scripts
  echo >&2 "Java detected, building natively"
  echo "time cdk"
elif command -v docker &>/dev/null; then
  # Echo to standard error since we need to use standard out to determine which command to run by other scripts
  echo >&2 "Java not detected, or Java version lower than the required version, or CDK not detected, using Docker"
  echo >&2 "If you have not tried this before it may take a minute or two to build the container, subsequent runs will be faster"

  set -e
  . ../get-aws-credentials.sh

  rm -rf master-cdk-temp
  cp -R ../../master-cdk master-cdk-temp
  time docker >&2 build -t $BUILD_TAG .
  rm -rf master-cdk-temp
  mkdir -p build/libs
  echo "time docker run --rm \
    -e AWS_REGION=$REGION \
    -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
    $BUILD_TAG \
    cdk"
else
  echo >&2 "Neither Java nor Docker was detected. At least one of these needs to be present to run this code"
  exit 1
fi
