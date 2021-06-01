# AccessTokenProvider for JupyterHub.

This class provides an implementation of the AccessTokenProvider interface used for the 
[Google Cloud Storage Connector](https://github.com/GoogleCloudDataproc/hadoop-connectors/tree/master/gcs).

## Usage

Instead of using a service account or other credentials for GCS authorization, this class uses a custom REST endpoint in 
Jupyterhub to provide access tokens. This custom endpoint must be configured in Jupyterhub by utilizing the
[TokenExchangeAuthenticator](../TokenExchangeAuthenticator) and set the `local_user_exposed_path` property. 
All handling of access token expiration, and token refresh will then be handled by the authentication mechanism in
Jupyterhub. 

The AccessTokenProvider must be configured by setting the following:

```bash
fs.gs.auth.access.token.provider.impl = no.ssb.dapla.gcs.token.JupyterHubAccessTokenProvider
```

See the
[Authentication](https://github.com/GoogleCloudDataproc/hadoop-connectors/blob/master/gcs/CONFIGURATION.md#authentication)
section for further details on how to configure the Google Cloud Storage connector.

In addition, the following environment variables must be set:

```bash
LOCAL_USER_PATH=/my-custom-path/userinfo
GCS_TOKEN_PROVIDER_KEY=google
```

These environment variables must correspond to the settings in the
[TokenExchangeAuthenticator](../TokenExchangeAuthenticator).

This implementation also relies on the environment variable `JUPYTERHUB_API_TOKEN`, which is automatically set by Jupyterhub.

