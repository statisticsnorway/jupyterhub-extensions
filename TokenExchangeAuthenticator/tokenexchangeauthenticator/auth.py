"""
TokenExchangeAuthenticator - a custom GenericOAuthenticator extension.
"""
import json
import time
from datetime import datetime, timedelta
from urllib import request, parse
from urllib.error import HTTPError

import jwt
from jupyterhub.handlers import BaseHandler
from jwt.algorithms import RSAAlgorithm
from oauthenticator.generic import GenericOAuthenticator
from tornado import web
from tornado.httpclient import HTTPRequest, HTTPClientError
from traitlets import Unicode, List, Bool


class TokenExchangeAuthenticator(GenericOAuthenticator):
    oidc_issuer = Unicode(
        default_value='',
        config=True,
        help="OIDC issuer URL for automatic discovery of configuration"
    )

    exchange_tokens = List(
        Unicode(),
        default_value=[],
        config=True,
        help="List of Identity Providers (issuers) to perform token exchange"
    )

    local_user_exposed_path = Unicode(
        default_value=None,
        allow_none=True,
        config=True,
        help="If set, exposes the user's access token(s) at this path"
    )

    hosted_domain = List(
        Unicode(),
        config=True,
        help="""List of domains used to restrict sign-in, e.g. mycollege.edu""",
    )

    verify_signature = Bool(
        default_value=True,
        config=True,
        help="If False, it will disable JWT signature verification of the access token."
    )

    def __init__(self, urlopen=request.urlopen, **kwargs):
        super().__init__(**kwargs)
        # Force auth state so that we can store the tokens in the user dict
        self.enable_auth_state = True

        if not self.oidc_issuer:
            raise Exception('No OIDC issuer url provided')

        self.log.info('Configuring OIDC from %s' % self.oidc_issuer)

        try:
            with urlopen('%s/.well-known/openid-configuration' % self.oidc_issuer) as response:
                data = json.loads(response.read())

                if not set(['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint',
                            'end_session_endpoint']).issubset(data.keys()):
                    raise Exception('Unable to retrieve OIDC necessary values')

                self.authorize_url = data['authorization_endpoint']
                self.token_url = data['token_endpoint']
                self.userdata_url = data['userinfo_endpoint']
                self.end_session_url = data['end_session_endpoint']

                if self.verify_signature:
                    jwks_uri = data['jwks_uri']
                    with request.urlopen(jwks_uri) as jkws_response:
                        jwk_data = json.loads(jkws_response.read())
                        self.public_key = RSAAlgorithm(RSAAlgorithm.SHA256).from_jwk(json.dumps(jwk_data['keys'][0]))
                        self.log.info('Got public key from %s' % jwks_uri)

        except HTTPError:
            self.log.error("Failure to retrieve the openid configuration")
            raise

        self.log.info("TokenExchangeAuthenticator initialised")

    async def authenticate(self, handler, data=None):
        self.log.info("Authenticating via TokenExchangeAuthenticator")
        user = await super().authenticate(handler, data=data)
        if not user:
            return None

        if self.hosted_domain:
            user_email = user['auth_state']['oauth_user']['email']
            user_email_domain = user_email.split('@')[1]
            if user_email_domain not in self.hosted_domain:
                self.log.warning(
                    "OAuth unauthorized domain attempt: %s", user_email
                )
                raise web.HTTPError(
                    403,
                    "Account domain @{} not authorized.".format(
                        user_email_domain
                    ),
                )

        try:
            user['auth_state']['exchanged_tokens'] = await self._exchange_tokens(user['auth_state']['access_token'])
        except KeyError:
            self.log.error('Exchanged tokens missing from auth_state for user %s', user['name'])
            handler.clear_cookie("jupyterhub-hub-login")
            handler.clear_cookie("jupyterhub-session-id")
            return None
        except HTTPClientError as error:
            self.log.error('Token exchange failed for user %s with response %s\n%s', user['name'], error,
                           error.response)
            handler.clear_cookie("jupyterhub-hub-login")
            handler.clear_cookie("jupyterhub-session-id")
            return None

        self.log.info("Authentication Successful for user: %s" % user['name'])
        return user

    async def pre_spawn_start(self, user, spawner):
        """Pass upstream_token to spawner via environment variable"""
        self.log.info('Calling pre_spawn_start for %s ' % user.name)
        # Retrieve user authentication info from JH
        auth_state = await user.get_auth_state()
        if not auth_state:
            # user has no auth state
            self.log.error('User has no auth state')
            return

        # update env var to pass to notebooks
        self.log.info('Starting notebook for: ' + user.name)

    async def refresh_user(self, user, handler=None):
        """
        Refresh user's oAuth tokens.
        This is called when user info is requested and
        has passed more than "auth_refresh_age" seconds.
        """
        try:
            # Retrieve user authentication info, decode, and check if refresh is needed
            auth_state = await user.get_auth_state()

            decoded_access_token = self._decode_token(auth_state['access_token'])
            decoded_refresh_token = self._decode_token(auth_state['refresh_token'], verify_signature=False)

            diff_access = decoded_access_token['exp'] - time.time()
            # If we request the offline_access scope, our refresh token won't have expiration
            diff_refresh = (decoded_refresh_token['exp'] - time.time()) if 'exp' in decoded_refresh_token else 0

            if diff_access > self.auth_refresh_age:
                # Access token is still valid - check exchange tokens
                if 'exchanged_tokens' in auth_state and await self._check_for_expired_exchange_tokens(auth_state):
                    self.log.info("New exchange_tokens updated for user %s" % user.name)
                    return {
                        'auth_state': auth_state
                    }
                else:
                    # All tokens are still valid and will stay until next refresh
                    self.log.info("All tokens are still valid and will stay until next refresh")
                    return True

            elif diff_refresh < 0:
                # Refresh token not valid, need to re-authenticate again
                self.log.info("Refresh token not valid, need to re-authenticate again")
                await handler.stop_single_user(user, user.spawner.name)
                handler.clear_cookie("jupyterhub-hub-login")
                handler.clear_cookie("jupyterhub-session-id")
                return None

            else:
                # We need to refresh access token (which will also refresh the refresh token)
                access_token, refresh_token = await self._refresh_token(auth_state['refresh_token'])
                # check signature for new access token, if it fails we catch in the exception below
                self.log.info("Refresh user token")
                self._decode_token(access_token)
                auth_state['access_token'] = access_token
                auth_state['refresh_token'] = refresh_token
                auth_state['exchanged_tokens'] = await self._exchange_tokens(access_token)

                self.log.info('User %s oAuth tokens refreshed' % user.name)
                return {
                    'auth_state': auth_state
                }
        except HTTPError as e:
            self.log.error("Failure calling the renew endpoint: %s (code: %s)" % (e.read(), e.code))

        except:
            self.log.error("Failed to refresh the oAuth tokens", exc_info=True)

        return False

    async def _exchange_token(self, issuer, token):
        self.log.info('Exchange tokens for: %s' % issuer)
        values = dict(
            grant_type='urn:ietf:params:oauth:grant-type:token-exchange',
            client_id=self.client_id,
            client_secret=self.client_secret,
            subject_token=token,
            requested_issuer=issuer,
            requested_token_type='urn:ietf:params:oauth:token-type:access_token',
            subject_token_type='urn:ietf:params:oauth:token-type:access_token'
        )
        req = HTTPRequest(
            self.token_url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=parse.urlencode(values).encode('ascii'),
        )
        # See https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.1
        # Token exchange reponse contains access_token and expires_in (not exp)
        data = await self.fetch(req)
        # Calculate exp. This is more convenient to use since 'expires_in' is just a snapshot of remaining seconds
        exp = round((datetime.now() + timedelta(seconds=data.get('expires_in', 0))).timestamp())
        self.log.info('Exchange token expires in %s secs (at time %s)' % (data.get('expires_in', 0), exp))
        return {
            'access_token': data.get('access_token', None),
            'expires_in': data.get('expires_in', 0),
            'exp': exp
        }

    async def _exchange_tokens(self, token):
        tokens = dict()
        for issuer in self.exchange_tokens:
            # TODO: use asyncio.gather here...
            tokens[issuer] = await self._exchange_token(issuer, token)
        return tokens

    async def _refresh_token(self, refresh_token):
        values = dict(
            grant_type='refresh_token',
            client_id=self.client_id,
            client_secret=self.client_secret,
            refresh_token=refresh_token
        )
        req = HTTPRequest(
            self.token_url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=parse.urlencode(values).encode('ascii'),
        )
        data = await self.fetch(req)
        return data.get('access_token', None), data.get('refresh_token', None)

    async def _check_for_expired_exchange_tokens(self, auth_state):
        modified = False
        for key in auth_state['exchanged_tokens']:
            exchange_token = auth_state['exchanged_tokens'][key]
            if 'exp' not in exchange_token:
                self.log.warn("Exchange token for '%s' is missing 'exp' property" % key)
                break
            diff_access = exchange_token['exp'] - time.time()
            # Use the same diff threshold as in refresh_user
            if diff_access < self.auth_refresh_age:
                self.log.info("Refresh token exchange for provider: %s" % key)
                new_token = await self._exchange_token(key, auth_state['access_token'])
                auth_state['exchanged_tokens'][key] = new_token
                modified = True
        return modified

    def get_handlers(self, app):
        handlers = super().get_handlers(app)
        if self.local_user_exposed_path:
            handlers.append((r'%s' % self.local_user_exposed_path, AuthHandler))
        return handlers

    def _decode_token(self, token, verify_signature=None):
        if verify_signature is None:
            verify_signature = self.verify_signature
        options = {
            "verify_signature": verify_signature,
            "verify_aud": False,
            "verify_exp": False
        }
        return jwt.decode(token, self.public_key if verify_signature else None,
                          options=options, algorithms=["HS256", "RS256"])


class AuthHandler(BaseHandler):
    """
    A custom request handler that returns user and auth state info
    """

    @web.authenticated
    async def get(self):
        user = await self.get_current_user()
        if user is None:
            self.log.info('User is none')
            # whoami can be accessed via oauth token
            user = self.get_current_user_oauth_token()
        if user is None:
            raise web.HTTPError(403)

        self.log.info('User is ' + user.name)
        # Force auth refresh to override the auth_refresh_age of 300 secs
        user = await self.refresh_auth(user, force=True)
        auth_state = await user.get_auth_state()
        if not auth_state:
            # user has no auth state
            self.log.error('User has no auth state')
            return

        self.write({
            "username": user.name,
            "access_token": auth_state['access_token'],
            "exchanged_tokens": auth_state['exchanged_tokens']
        })
