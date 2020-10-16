package com.awslabs.iatt.spe.serverless.gwt.client;

public class PageTokenFilter extends QueryTokenFilter {
    public static final String PAGE = "page";

    public PageTokenFilter(String value) {
        super(PAGE, value);
    }
}
