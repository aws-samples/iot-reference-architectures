plugins {
    kotlin("jvm") version "1.4.21"
    id("application")
    id("java")
    id("idea")
    id("java-library")
    id("com.github.ben-manes.versions") version "0.36.0"
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(8))
    }
}

val gradleDependencyVersion = "6.7.1"

tasks.wrapper {
    gradleVersion = gradleDependencyVersion
    distributionType = Wrapper.DistributionType.ALL
}

// Use the MasterApp main class when the JAR is invoked directly
application.mainClass.set("com.awssamples.MasterApp")

tasks.distZip { enabled = false }
tasks.distTar { enabled = false }

// Specify all of our dependency versions
val awsCdkVersion = "1.80.0"
val vavrVersion = "0.10.3"
val slf4jVersion = "2.0.0-alpha1"
val jcabiVersion = "0.19.0"
val commonsLangVersion = "3.11"
val commonsIoVersion = "2.8.0"
val ztZipVersion = "1.14"
val resultsIteratorForAwsJavaSdkVersion = "11.0.7"
val daggerVersion = "2.30.1"
val junitVersion = "4.13.1"
val awsLambdaServletVersion = "0.1.3"
val awsCdkConstructsForJavaVersion = "0.1.40"
val gsonVersion = "2.8.6"

repositories {
    mavenCentral()
    mavenLocal()
    maven(url = "https://repo.gradle.org/gradle/libs-releases-local/")
    maven(url = "https://jitpack.io")
}

dependencies {
    // Dagger code generation
    annotationProcessor("com.google.dagger:dagger-compiler:$daggerVersion")

    // Dependency injection with Dagger
    api("com.google.dagger:dagger:$daggerVersion")

    implementation("org.slf4j:slf4j-log4j12:$slf4jVersion")
    implementation("com.jcabi:jcabi-log:$jcabiVersion")

    api("software.amazon.awscdk:core:$awsCdkVersion")
    api("software.amazon.awscdk:iam:$awsCdkVersion")
    api("software.amazon.awscdk:sqs:$awsCdkVersion")
    api("software.amazon.awscdk:iot:$awsCdkVersion")
    api("software.amazon.awscdk:lambda:$awsCdkVersion")
    api("software.amazon.awscdk:dynamodb:$awsCdkVersion")
    api("software.amazon.awscdk:apigateway:$awsCdkVersion")
    implementation("io.vavr:vavr:$vavrVersion")
    api("org.gradle:gradle-tooling-api:$gradleDependencyVersion")
    implementation("org.apache.commons:commons-lang3:$commonsLangVersion")
    implementation("commons-io:commons-io:$commonsIoVersion")
    api("org.zeroturnaround:zt-zip:$ztZipVersion")
    api("com.github.awslabs:results-iterator-for-aws-java-sdk:$resultsIteratorForAwsJavaSdkVersion")
    api("com.github.aws-samples:aws-lambda-servlet:$awsLambdaServletVersion")

    api("com.github.aws-samples:aws-cdk-constructs-for-java:$awsCdkConstructsForJavaVersion")
//    api("local:aws-cdk-constructs-for-java:1.0-SNAPSHOT")
    api("com.google.code.gson:gson:$gsonVersion")

    testImplementation("junit:junit:$junitVersion")
}