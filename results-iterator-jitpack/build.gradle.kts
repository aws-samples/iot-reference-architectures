plugins {
    id("java")
    id("application")
    id("idea")

    // Creates fat JAR
    id("com.github.johnrengelman.shadow") version "7.0.0"

    // Adds dependencyUpdates task
    id("com.github.ben-manes.versions") version "0.39.0"
}

val gradleDependencyVersion = "7.0.2"

tasks.wrapper {
    gradleVersion = gradleDependencyVersion
    distributionType = Wrapper.DistributionType.ALL
}

application.mainClass.set("com.awslabs.aws.iot.resultsiterator.Example")

tasks.distZip { enabled = false }
tasks.distTar { enabled = false }
tasks.shadowDistZip { enabled = false }
tasks.shadowDistTar { enabled = false }

// Specify all of our dependency versions
val resultsIteratorForAwsJavaSdkVersion = "29.0.9"
val junitVersion = "4.13.2"
val awsSdk2Version = "2.16.85"
val vavrVersion = "0.10.3"
val jcabiVersion = "0.19.0"

group = "com.awslabs.aws.iot.resultsiterator.jitpack.Example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()

    maven(url = "https://repo.gradle.org/gradle/libs-releases-local/")
    maven(url = "https://plugins.gradle.org/m2/")
    maven(url = "https://jitpack.io")
}

dependencies {
    implementation("com.github.awslabs:results-iterator-for-aws-java-sdk:$resultsIteratorForAwsJavaSdkVersion")
    implementation("software.amazon.awssdk:iot:$awsSdk2Version")
    implementation("io.vavr:vavr:$vavrVersion")

    testImplementation("junit:junit:$junitVersion")
    testImplementation("com.jcabi:jcabi-log:$jcabiVersion")
}
