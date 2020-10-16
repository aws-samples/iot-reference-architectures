#!/usr/bin/bash env

AWS_CLI_ERROR_MESSAGE_PREFIX="No"
AWS_CLI_ERROR_MESSAGE_SUFFIX="found via aws configure get, do you have the AWS CLI configured on this system? This command does NOT retrieve credentials from EC2 instance metadata."

# Allow failures, we will catch them
set +e

if [ ! command -v aws ] &>/dev/null; then
  echo >&2 "AWS CLI must be installed and configured for deployments"
  exit 1
fi

# Is the AWS CLI configured?
AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id)

if [ $? -ne 0 ]; then
  echo >&2 $AWS_CLI_ERROR_MESSAGE_PREFIX access key ID $AWS_CLI_ERROR_MESSAGE_SUFFIX
  exit 1
fi

AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key)

if [ $? -ne 0 ]; then
  echo >&2 $AWS_CLI_ERROR_MESSAGE_PREFIX secret access key $AWS_CLI_ERROR_MESSAGE_SUFFIX
  exit 1
fi

REGION=$(aws configure get region)

if [ $? -ne 0 ]; then
  echo >&2 $AWS_CLI_ERROR_MESSAGE_PREFIX region $AWS_CLI_ERROR_MESSAGE_SUFFIX
  exit 1
fi

export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export REGION
