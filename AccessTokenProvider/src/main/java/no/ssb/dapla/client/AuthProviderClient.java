package no.ssb.dapla.client;

import com.google.gson.Gson;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.concurrent.TimeUnit;

public class AuthProviderClient {

    private final Logger log = LoggerFactory.getLogger(this.getClass());
    private OkHttpClient client;
    private String authProviderUrl;

    public AuthProviderClient(String authProviderUrl) {
        this.authProviderUrl = authProviderUrl;
        OkHttpClient.Builder builder = new OkHttpClient.Builder().callTimeout(10, TimeUnit.SECONDS);
        builder.addInterceptor(new BearerTokenInterceptor(new JHubTokenSupplier()));
        client = builder.build();
    }

    public AuthResponse getAuth() {
        Request request = new Request.Builder()
                .url(this.authProviderUrl).get().build();

        try (Response response = client.newCall(request).execute()) {
            String json = getJson(response);
            handleErrorCodes(response, json);
            Gson gson = new Gson();
            return gson.fromJson(json, AuthResponse.class);
        } catch (IOException e) {
            log.error("getAccessToken failed", e);
            throw new AuthProviderException(e);
        }
    }

    private String getJson(Response response) throws IOException {
        ResponseBody body = response.body();
        if (body == null) return null;
        return body.string();
    }

    private void handleErrorCodes(Response response, String body) {
        if (response.code() == HttpURLConnection.HTTP_UNAUTHORIZED || response.code() == HttpURLConnection.HTTP_FORBIDDEN) {
            throw new AuthProviderException("Access denied", body);
        } else if (response.code() == HttpURLConnection.HTTP_NOT_FOUND) {
            throw new AuthProviderException("Invalid URL: " + this.authProviderUrl);
        } else if (response.code() < 200 || response.code() >= 400) {
            throw new AuthProviderException("Unknown error: " + response, body);
        }
    }

    public static class AuthProviderException extends RuntimeException {
        private final String body;

        public AuthProviderException(Throwable cause) {
            super(cause);
            this.body = null;
        }

        public AuthProviderException(String message) {
            this(message, null);
        }

        public AuthProviderException(String message, String body) {
            super(message);
            this.body = body;
        }

        @Override
        public String getMessage() {
            if (body == null) {
                return super.getMessage();
            }
            return super.getMessage() + "\n" + body;
        }
    }

}
