package com.awssamples.gradle;

import io.vavr.control.Try;
import org.gradle.tooling.BuildLauncher;
import org.gradle.tooling.GradleConnector;
import org.gradle.tooling.ProjectConnection;

import java.io.File;

public class GradleSupport {
    public static void buildJar(File projectDirectoryFile) {
        ProjectConnection projectConnection = GradleConnector.newConnector()
                .forProjectDirectory(projectDirectoryFile)
                .connect();

        Try.withResources(() -> projectConnection)
                .of(GradleSupport::runBuild)
                .get();
    }

    public static Void runBuild(ProjectConnection projectConnection) {
        // Build with gradle and send the output to stderr
        BuildLauncher build = projectConnection.newBuild();
        build.forTasks("build");
        build.setStandardOutput(System.err);
        build.run();

        return null;
    }
}
