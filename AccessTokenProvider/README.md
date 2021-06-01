# AccessTokenProvider for JupyterHub.

This class provides an implementation of the AccessTokenProvider interface used for the 
[Google Cloud Storage Connector](https://github.com/GoogleCloudDataproc/hadoop-connectors/tree/master/gcs).

## Usage

Instead of using a service account or other credentials for GCS authorization, this class uses custom REST endpoint in 
Jupyterhub to provide access tokens. And upon access token expiration, the utility to refresh. See the 
[Authentication](https://github.com/GoogleCloudDataproc/hadoop-connectors/blob/master/gcs/CONFIGURATION.md#authentication)
section for further details on how to configure the connector with this class.