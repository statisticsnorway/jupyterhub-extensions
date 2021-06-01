package no.ssb.dapla.gcs.token;

import com.google.cloud.hadoop.util.AccessTokenProvider;
import no.ssb.dapla.client.AuthProviderClient;
import no.ssb.dapla.client.AuthResponse;
import org.apache.hadoop.conf.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An AccessTokenProvider implementation that retrieves access token from Jupyterhub.
 */
public final class JupyterHubAccessTokenProvider implements AccessTokenProvider {

    public static final String AUTH_PROVIDER_URL_KEY = "LOCAL_USER_PATH";
    public static final String GCS_TOKEN_KEY = "GCS_TOKEN_PROVIDER_KEY";

    private Configuration config;
    private AccessToken accessToken;
    private final String gcsTokenKey;
    private static final Logger LOG = LoggerFactory.getLogger(JupyterHubAccessTokenProvider.class);
    private final AuthProviderClient client = new AuthProviderClient(System.getenv().get(AUTH_PROVIDER_URL_KEY));

    private final static AccessToken EXPIRED_TOKEN = new AccessToken("", -1L);

    public JupyterHubAccessTokenProvider() {
        this.accessToken = EXPIRED_TOKEN;
        this.gcsTokenKey = System.getenv().get(GCS_TOKEN_KEY);

    }

    @Override
    public AccessToken getAccessToken() {
        return this.accessToken;
    }

    @Override
    public void refresh() {
        AuthResponse response = client.getAuth();
        if (response.getExchangedTokens().isEmpty()) {
            throw new IllegalStateException("Exchange tokens missing. Can not retrieve access tokens for GCS");
        } else {
            AuthResponse.ExchangedToken token = response.getExchangedTokens().get(this.gcsTokenKey);
            accessToken = new AccessToken(token.getAccessToken(), token.getExpirationTimeMilliSeconds());
        }
    }

    @Override
    public void setConf(Configuration config) {
        this.config = config;
    }

    @Override
    public Configuration getConf() {
        return this.config;
    }

}