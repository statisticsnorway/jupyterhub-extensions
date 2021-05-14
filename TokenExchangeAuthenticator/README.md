# TokenExchangeAuthenticator

This Authenticator is built on top of [OAuthenticator](https://github.com/jupyterhub/oauthenticator), and authenticates 
users using OIDC and retrieves external Identity Provider (IDP) tokens
using [token exchange](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange). This implementation is
compatible with Keycloak as an [Identity Broker](https://www.keycloak.org/docs/latest/server_admin/#_identity_broker)
and Google as an external IDP (see [Internal Token to External Token Exchange](https://www.keycloak.org/docs/latest/securing_apps/#internal-token-to-external-token-exchange)). 

It also implements a refresh mechanism, ensuring that both the internal access token as well as any external IDP
tokens are updated individually. If the update is not possible, it forces a re-authentication of the user.

## Sequence diagram
The OIDC + token exchange flow may be illustrated like in the following sequence diagram:

![OIDC with token exchange](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/statisticsnorway/jupyterhub-extensions/master/TokenExchangeAuthenticator/token-exchange.puml)

## Installation

```bash
pip install tokenexchangeauthenticator
```

## Usage

In your JupyterHub config file, set the authenticator and configure it:

```python
# Enable the authenticator
c.JupyterHub.authenticator_class = 'tokenexchangeauthenticator.TokenExchangeAuthenticator'
c.TokenExchangeAuthenticator.username_key = 'preferred_username'
c.TokenExchangeAuthenticator.userdata_params = {'state': 'state', 'kc_idp_hint': 'google'}
c.TokenExchangeAuthenticator.logout_redirect_uri = 'https://my.domain.com/logout'
c.TokenExchangeAuthenticator.oauth_callback_url = 'https://my.domain.com/oauth_callback'

# Specify the issuer url, to get all the endpoints automatically from .well-known/openid-configuration
c.TokenExchangeAuthenticator.oidc_issuer = 'https://my.keycloak.com/auth/realms/myrealm'

# If you need to set a different scope, like adding the offline option for longer lived refresh token
c.TokenExchangeAuthenticator.scope = ['openid', 'email', 'offline_access']
# Request access tokens for other services by passing their id's (this uses the token exchange mechanism)
c.TokenExchangeAuthenticator.exchange_tokens = ['google']
```

#### Note on Google's authorization server
Google's authorization server only provideds the `refresh_token` in the response to the initial login request.
Hence, the Identity Broker (e.g. Keycloak) will only get the refresh token on the first login so that subsequent token 
refresh may stop working (see [issue on stack overflow](https://stackoverflow.com/questions/62700314/keycloak-only-gets-google-refresh-token-on-first-login)).
This can be remedied by prompting for re-consent at every login like this:

```python
# This will force the retrieval of a refresh_token on every login
c.TokenExchangeAuthenticator.extra_authorize_params = {'prompt': 'consent'}
```

It's also necessary to configure the client ID and secret. This may be set directly like this:
```python
# This will force the retrieval of a refresh_token on every login
c.TokenExchangeAuthenticator.client_id = 'client-id'
c.TokenExchangeAuthenticator.client_secret = 'secret'
```

Or by setting the following environment
variables:

```bash
OAUTH_CLIENT_ID=client_id
OAUTH_CLIENT_SECRET=client_secret
```

#### Expose the user's tokens

The user's tokens are stored using Jupyterhub's [authentication state](https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html#authentication-state). 
These can optionally be exposed at a custom path which will only be accessible inside the user's single-user notebook. 
The path can be customised by setting:
```python
# If set, exposes the user's access token(s) at this relative path
c.TokenExchangeAuthenticator.local_user_exposed_path = '/my-custom-path/userinfo'
```

## Running tests
To run the tests locally:

```
$ pip install --upgrade --pre -r test-requirements.txt
```

```
$ pytest -v ./tokenexchangeauthenticator/tests/
```
Or you run a specific test file with:

```
$ pytest -v ./tokenexchangeauthenticator/tests/<test-file-name>
```