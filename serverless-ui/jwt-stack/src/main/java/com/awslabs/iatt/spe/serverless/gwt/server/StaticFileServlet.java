package com.awslabs.iatt.spe.serverless.gwt.server;

import com.aws.samples.lambda.servlet.LambdaWebServlet;
import com.aws.samples.lambda.servlet.servlets.AbstractStaticFileServlet;
import com.aws.samples.lambda.servlet.servlets.MimeHelper;

import javax.servlet.annotation.WebServlet;
import java.io.File;
import java.io.InputStream;
import java.util.Optional;

@WebServlet(name = "StaticFileServlet", displayName = "StaticFileServlet", urlPatterns = {"/*"}, loadOnStartup = 1)
@LambdaWebServlet
public class StaticFileServlet extends AbstractStaticFileServlet {
    private final MimeHelper mimeHelper = new MimeHelper() {
        @Override
        public String detect(File file) {
            return detect(file.getName(), null);
        }

        @Override
        public String detect(InputStream file) {
            return null;
        }

        @Override
        public String detect(String filename, InputStream file) {
            if (filename.endsWith(".woff2") ||
                    filename.endsWith(".woff") ||
                    filename.endsWith(".ttf") ||
                    filename.endsWith(".eot")) {
                return "font/octet-stream";
            } else if (filename.endsWith(".svg") ||
                    filename.endsWith(".svgz")) {
                return "image/svg+xml";
            }

            return null;
        }
    };
    private final Optional<MimeHelper> optionalMimeHelper = Optional.of(mimeHelper);

    @Override
    public Optional<MimeHelper> getOptionalMimeHelper() {
        return optionalMimeHelper;
    }

    @Override
    public String getPrefix() {
        return "/";
    }
}
