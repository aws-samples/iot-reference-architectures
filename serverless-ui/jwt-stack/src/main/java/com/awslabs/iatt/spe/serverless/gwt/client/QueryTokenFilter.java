package com.awslabs.iatt.spe.serverless.gwt.client;

import org.dominokit.domino.history.DefaultNormalizedToken;
import org.dominokit.domino.history.HistoryToken;
import org.dominokit.domino.history.NormalizedToken;
import org.dominokit.domino.history.TokenFilter;

public class QueryTokenFilter implements TokenFilter {
    private final String queryParam;
    private final String value;

    public QueryTokenFilter(String queryParam, String value) {
        this.queryParam = queryParam;
        this.value = value;
    }

    @Override
    public boolean filter(HistoryToken token) {
        return token.hasQueryParameter(queryParam) && token.getQueryParameter(queryParam).equals(value);
    }

    @Override
    public NormalizedToken normalizeToken(String token) {
        return new DefaultNormalizedToken(token);
    }
}