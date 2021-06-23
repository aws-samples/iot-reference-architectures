plugins {
    kotlin("jvm") version "1.5.10"
    id("application")
    id("java")
    id("idea")
    id("java-library")

    // Creates fat JAR
    id("com.github.johnrengelman.shadow") version "7.0.0"
}

java.toolchain.languageVersion.set(JavaLanguageVersion.of(11))

val gradleDependencyVersion = "7.0"

tasks.wrapper {
    gradleVersion = gradleDependencyVersion
    distributionType = Wrapper.DistributionType.ALL
}

// Required for shadow JAR but not used
application.mainClass.set("not-applicable")

repositories {
    mavenCentral()

    maven(url = "https://plugins.gradle.org/m2/")
    maven(url = "https://repo.gradle.org/gradle/libs-releases-local/")
    maven(url = "https://jitpack.io")
}

// Specify all of our dependency versions
val slf4jVersion = "1.7.30"
val gsonVersion = "2.8.7"
val awsSdk2Version = "2.16.85"
val junitVersion = "4.13.2"
val awsLambdaJavaCoreVersion = "1.2.1"
val vavrVersion = "0.10.3"
val vavrGsonVersion = "0.10.2"
val commonsCodecVersion = "1.15"
val resultsIteratorForAwsJavaSdkVersion = "29.0.9"
val xrayVersion = "2.7.1"

group = "com.awssamples.iot.dynamodb.Api"
version = "1.0-SNAPSHOT"

dependencies {
    implementation("com.google.code.gson:gson:$gsonVersion")

    implementation("com.amazonaws:aws-lambda-java-core:$awsLambdaJavaCoreVersion")

    implementation("software.amazon.awssdk:sqs:$awsSdk2Version")
    implementation("software.amazon.awssdk:dynamodb:$awsSdk2Version")
    implementation("software.amazon.awssdk:iotdataplane:$awsSdk2Version")
    implementation("software.amazon.awssdk:iot:$awsSdk2Version")

    // For converting payloads to hex strings
    implementation("commons-codec:commons-codec:$commonsCodecVersion")

    // For profiling Lambda functions
//    implementation("com.amazonaws:aws-xray-recorder-sdk-aws-sdk-v2-instrumentor:$xrayVersion"

    implementation("org.slf4j:slf4j-log4j12:$slf4jVersion")

    implementation("io.vavr:vavr:$vavrVersion")
    implementation("io.vavr:vavr-gson:$vavrGsonVersion")

    implementation("com.github.awslabs:results-iterator-for-aws-java-sdk:$resultsIteratorForAwsJavaSdkVersion")

    testImplementation("junit:junit:$junitVersion")
}
