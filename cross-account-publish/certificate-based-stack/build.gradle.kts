plugins {
    kotlin("jvm") version "1.5.10"
    id("application")
    id("java")
    id("idea")
    id("java-library")

    // Creates fat JAR
    id("com.github.johnrengelman.shadow") version "7.0.0"

    // Adds dependencyUpdates task
    id("com.github.ben-manes.versions") version "0.39.0"
}

extensions.findByName("buildScan")?.withGroovyBuilder {
    setProperty("termsOfServiceUrl", "https://gradle.com/terms-of-service")
    setProperty("termsOfServiceAgree", "yes")
}

idea.module.isDownloadSources = true
idea.module.isDownloadJavadoc = true

java.toolchain.languageVersion.set(JavaLanguageVersion.of(8))

// Required for shadow JAR but we don't use it. Can not be replaced with application.mainClass.set.
application.mainClassName = "not-necessary"

val gradleDependencyVersion = "7.1"

tasks.wrapper {
    gradleVersion = gradleDependencyVersion
    distributionType = Wrapper.DistributionType.ALL
}

repositories {
    mavenCentral()
    maven(url = "https://jitpack.io")
    // Required for Gradle Tooling API
    maven(url = "https://repo.gradle.org/gradle/libs-releases-local/")
}

tasks.distZip { enabled = false }
tasks.distTar { enabled = false }
tasks.shadowDistZip { enabled = false }
tasks.shadowDistTar { enabled = false }

tasks.shadowJar {
    // AWS Lambda specific - fixes "StatusLogger Unrecognized format specifier [d]" errors, from https://stackoverflow.com/questions/48033792/log4j2-error-statuslogger-unrecognized-conversion-specifier
    transform(com.github.jengelman.gradle.plugins.shadow.transformers.Log4j2PluginsCacheFileTransformer::class.java)
}

val awsLambdaJavaCoreVersion = "1.2.1"
val awsLambdaJavaLog4j2Version = "1.2.0"
val log4jVersion = "2.14.1"
val jacksonVersion = "2.12.1"
val vavrVersion = "0.10.3"
val awsSdk2Version = "2.16.99"
val gwtServletVersion = "2.9.0"
val junitVersion = "4.13.2"
val slf4jSimpleVersion = "1.7.30"
val vertxVersion = "4.0.2"
val jjwtVersion = "3.13.0"
val awsCdkConstructsForJava = "0.14.0"
val awsLambdaServletVersion = "0.2.4"
val daggerVersion = "2.37"
val resultsIteratorForAwsJavaSdkVersion = "29.0.7"
val bouncyCastleVersion = "1.69"

dependencies {
    implementation("io.vavr:vavr:$vavrVersion")
    implementation("io.vavr:vavr-jackson:$vavrVersion")

    // Lambda core and logging
    implementation("com.amazonaws:aws-lambda-java-core:$awsLambdaJavaCoreVersion")
    implementation("org.apache.logging.log4j:log4j-api:$log4jVersion")
    implementation("org.apache.logging.log4j:log4j-core:$log4jVersion")
    api("org.apache.logging.log4j:log4j-slf4j18-impl:$log4jVersion")
    api("com.amazonaws:aws-lambda-java-log4j2:$awsLambdaJavaLog4j2Version")

    // Dagger code generation
    annotationProcessor("com.google.dagger:dagger-compiler:$daggerVersion")

    // Dependency injection with Dagger
    implementation("com.google.dagger:dagger:$daggerVersion")

    // Required for X.509 certificate features
    implementation("com.github.awslabs:results-iterator-for-aws-java-sdk:$resultsIteratorForAwsJavaSdkVersion")

    // AWS SDK v2
    implementation("software.amazon.awssdk:iot:$awsSdk2Version")
    implementation("software.amazon.awssdk:apache-client:$awsSdk2Version")

    implementation("com.github.aws-samples:aws-cdk-constructs-for-java:$awsCdkConstructsForJava")
    annotationProcessor("com.github.aws-samples:aws-cdk-constructs-for-java:$awsCdkConstructsForJava")

    testImplementation("junit:junit:$junitVersion")

    // To force dependabot to update the Gradle wrapper dependency
    testImplementation("org.gradle:gradle-tooling-api:$gradleDependencyVersion")

    // For certificate based authentication
    implementation("org.bouncycastle:bcprov-jdk15on:$bouncyCastleVersion")
    implementation("org.bouncycastle:bcpkix-jdk15on:$bouncyCastleVersion")
}
