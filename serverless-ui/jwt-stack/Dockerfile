FROM ubuntu AS awsIotDeviceSdk

# Get curl
RUN apt-get -y update
RUN apt-get -y install curl

# Get n to install NodeJS
RUN curl -L https://raw.githubusercontent.com/tj/n/master/bin/n -o n
RUN bash n lts

# Install the source for the AWS IoT Device SDK for Javascript v1
RUN npm install aws-iot-device-sdk
WORKDIR node_modules/aws-iot-device-sdk

# Install browserify to build the SDK into a browser bundle
RUN npm install -g browserify

# Unfortunate hack because the first time browserize runs in Docker it fails
# Include cognitoidentity so browserize doesn't include the entire AWS SDK
RUN AWS_SERVICES=cognitoidentity npm run-script browserize; AWS_SERVICES=cognitoidentity npm run-script browserize

# Install uglify-js to reduce the bundle size (from ~1.4 MB -> ~488k)
RUN npm install -g uglify-js

# Reduce the bundle size
RUN uglifyjs browser/aws-iot-sdk-browser-bundle.js -c -m -o browser/aws-iot-sdk-browser-bundle-min-uglifyjs.js

FROM ubuntu AS builder

# Get curl and OpenJDK
RUN apt-get -y update
RUN apt-get -y install curl
RUN apt-get -y install openjdk-8-jdk

# Get n to install NodeJS
RUN curl -L https://raw.githubusercontent.com/tj/n/master/bin/n -o n
RUN bash n lts

# Install CDK
RUN npm install -g aws-cdk@1.82.0

COPY build.gradle.kts /serverless-ui/jwt-stack/
COPY gradlew /serverless-ui/jwt-stack/
COPY gradle/wrapper/ /serverless-ui/jwt-stack/gradle/wrapper
WORKDIR /serverless-ui/jwt-stack

# Run the Gradle clean task to cache Gradle early so we don't have to rebuild the cache each time the source changes
RUN ./gradlew clean --no-daemon

# Copy the code for the stack and the Javascript AWS IoT device SDK
COPY src /serverless-ui/jwt-stack/src
COPY --from=awsIotDeviceSdk node_modules/aws-iot-device-sdk/browser/aws-iot-sdk-browser-bundle-min-uglifyjs.js /serverless-ui/jwt-stack/src/main/webapp/aws-iot-sdk-browser-bundle-min.js
COPY cdk.json /serverless-ui/jwt-stack

# Build the code here so we can cache it before we run "cdk deploy"
RUN ./gradlew build --no-daemon

# Copy the master-cdk project and build it so it is cached
COPY master-cdk-temp /master-cdk
WORKDIR /master-cdk
RUN ./gradlew build --no-daemon

# Set the working directory to the stack's directory
WORKDIR /serverless-ui/jwt-stack
