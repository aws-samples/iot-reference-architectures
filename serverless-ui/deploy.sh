#!/usr/bin/env bash

set -e

. ./project-variables.sh

COMMAND=$(../get-command.sh $BUILD_TAG $JAR)

$COMMAND deploy --require-approval never
