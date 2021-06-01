package no.ssb.dapla.client;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.*;

public class AuthProviderClientTest {

    private MockWebServer server;

    @Before
    public void setUp() throws IOException {
        this.server = new MockWebServer();
        this.server.start();
    }

    @Test
    public void testGetAuth() {
        server.enqueue(new MockResponse()
                .setBody("{\n" +
                        "  \"access_token\": \"local-access-token\",\n" +
                        "  \"exchanged_tokens\": {\n" +
                        "    \"google\": {\n" +
                        "      \"access_token\": \"google-access-token\",\n" +
                        "      \"exp\": 1839\n" +
                        "    }\n" +
                        "  }\n" +
                        "}\n")
                .setResponseCode(200));
        AuthProviderClient authProviderClient = new AuthProviderClient(server.url("/auth").toString());
        AuthResponse response = authProviderClient.getAuth();
        assertThat(response.getAccessToken()).isEqualTo("local-access-token");
        assertThat(response.getExchangedTokens().get("google").getAccessToken()).isEqualTo("google-access-token");
        assertThat(response.getExchangedTokens().get("google").getExp()).isEqualTo(1839);

    }
}
