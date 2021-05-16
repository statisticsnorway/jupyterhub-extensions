import json
from datetime import datetime, timedelta
from unittest import mock
from unittest.mock import MagicMock
from unittest.mock import Mock

import jwt
import time
from oauthenticator.generic import GenericOAuthenticator
from pytest import fixture, raises
from tornado.web import HTTPError

from .mocks import setup_oauth_mock, mock_handler
from ..auth import TokenExchangeAuthenticator, SSOLogoutHandler, AuthHandler


def openid_configuration():
    """Mock response from .well-known/openid-configuration"""
    return {
        "issuer": "https://mydomain.com/auth/realms/ssb",
        "authorization_endpoint": "https://mydomain.com/auth/realms/ssb/protocol/openid-connect/auth",
        "token_endpoint": "https://mydomain.com/auth/realms/ssb/protocol/openid-connect/token",
        "userinfo_endpoint": "https://mydomain.com/auth/realms/ssb/protocol/openid-connect/userinfo",
        "end_session_endpoint": "https://mydomain.com/auth/realms/ssb/protocol/openid-connect/logout",
    }


def user_model(username, **kwargs):
    """Return a user model"""
    user = {
        'username': username,
        'scope': 'basic',
    }
    user.update(kwargs)
    return user


def urlopen(request):
    cm = MagicMock()
    cm.__enter__.return_value.read.return_value = json.dumps(openid_configuration())
    return cm


def get_authenticator(**kwargs):
    return TokenExchangeAuthenticator(
        oidc_issuer='https://mydomain.com/auth/realms/ssb/auth/realms/ssb',
        urlopen=urlopen,
        **kwargs
    )


@fixture
def oauth_client(client):
    setup_oauth_mock(
        client,
        host='mydomain.com',
        access_token_path='/auth/realms/ssb/protocol/openid-connect/token',
        user_path='/auth/realms/ssb/protocol/openid-connect/userinfo',
    )
    return client


async def test_authenticator(oauth_client):
    with mock.patch.object(GenericOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = oauth_client
        authenticator = get_authenticator()

        handler = oauth_client.handler_for_user(user_model('john.doe', email='fake@email.com'))
        user_info = await authenticator.authenticate(handler)
        assert sorted(user_info) == ['auth_state', 'name']
        name = user_info['name']
        assert name == 'john.doe'
        auth_state = user_info['auth_state']
        assert 'access_token' in auth_state
        assert 'oauth_user' in auth_state
        assert 'refresh_token' in auth_state
        assert 'scope' in auth_state


async def test_authenticator_with_local_user_exposed_path(oauth_client):
    with mock.patch.object(GenericOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = oauth_client
        authenticator = get_authenticator(local_user_exposed_path='/custom-api/userinfo')

        handler = oauth_client.handler_for_user(user_model('john.doe', email='fake@email.com'))
        await authenticator.authenticate(handler)
        handlers = [handler for _, handler in authenticator.get_handlers(None)]
        assert any([h == AuthHandler for h in handlers])


async def test_authenticator_with_token_exchange(oauth_client):
    with mock.patch.object(GenericOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = oauth_client
        authenticator = get_authenticator(exchange_tokens=['ext_idp'])

        handler = oauth_client.handler_for_user(user_model('john.doe', email='fake@email.com'))
        user_info = await authenticator.authenticate(handler)
        assert sorted(user_info) == ['auth_state', 'name']
        name = user_info['name']
        assert name == 'john.doe'
        auth_state = user_info['auth_state']
        assert 'access_token' in auth_state
        assert 'oauth_user' in auth_state
        assert 'refresh_token' in auth_state
        assert 'scope' in auth_state
        assert 'exchanged_tokens' in auth_state
        assert 'ext_idp' in auth_state['exchanged_tokens']
        assert 'access-token' in auth_state['exchanged_tokens']['ext_idp']
        assert 'exp' in auth_state['exchanged_tokens']['ext_idp']


async def test_authenticator_refresh_all_valid(oauth_client):
    with mock.patch.object(GenericOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = oauth_client
        authenticator = get_authenticator()

        handler = oauth_client.handler_for_user(user_model('john.doe', email='fake@email.com'))
        user_info = await authenticator.authenticate(handler)

        class SimpleUser:
            def __init__(self, user_info):
                self.user_info = user_info
                dt = datetime.now() + timedelta(hours=1)
                user_info['access_token'] = jwt.encode({'exp': dt}, 'secret', algorithm='HS256')
                user_info['refresh_token'] = jwt.encode({'exp': dt}, 'secret', algorithm='HS256')
                user_info['exchanged_tokens'] = {
                    'external-idp-key': {
                        'access_token': 'not-a-jwt-token',
                        'exp': dt.timestamp()
                    }
                }

            async def get_auth_state(self):
                return self.user_info

        result = await authenticator.refresh_user(SimpleUser(user_info))
        # Still valid
        assert result is True


async def test_authenticator_refresh_token_exchange(oauth_client):
    with mock.patch.object(GenericOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = oauth_client
        authenticator = get_authenticator()

        handler = oauth_client.handler_for_user(user_model('john.doe', email='fake@email.com'))
        user_info = await authenticator.authenticate(handler)

        class SimpleUser:
            def __init__(self, user_info):
                self.user_info = user_info
                dt = datetime.now() + timedelta(hours=1)
                user_info['access_token'] = jwt.encode({'exp': dt}, 'secret', algorithm='HS256')
                user_info['refresh_token'] = jwt.encode({'exp': dt}, 'secret', algorithm='HS256')
                user_info['exchanged_tokens'] = {
                    'external-idp-key': {
                        'access_token': 'not-a-jwt-token',
                        # simulate expired exchange token
                        'exp': int(round(time.time()) - 100)
                    }
                }

            async def get_auth_state(self):
                return self.user_info

        result = await authenticator.refresh_user(SimpleUser(user_info))
        auth_state = result['auth_state']
        assert 'exchanged_tokens' in auth_state


async def test_hosted_domain(oauth_client):
    with mock.patch.object(GenericOAuthenticator, 'http_client') as fake_client:
        fake_client.return_value = oauth_client
        authenticator = get_authenticator(hosted_domain=['email.com', 'mycollege.edu'])

        handler = oauth_client.handler_for_user(user_model('john.doe', email='fake@email.com'))
        user_info = await authenticator.authenticate(handler)
        email = user_info['auth_state']['oauth_user']['email']
        assert email == 'fake@email.com'

        handler = oauth_client.handler_for_user(user_model('john.doe', email='notallowed@notemail.com'))
        with raises(HTTPError) as exc:
            await authenticator.authenticate(handler)
        assert exc.value.status_code == 403


async def test_custom_logout(monkeypatch):
    login_url = "http://myhost/login"
    authenticator = get_authenticator()
    logout_handler = mock_handler(SSOLogoutHandler,
                                  authenticator=authenticator,
                                  login_url=login_url)
    logout_handler.clear_login_cookie = Mock()
    logout_handler.clear_cookie = Mock()
    logout_handler._jupyterhub_user = Mock()
    monkeypatch.setitem(logout_handler.settings, 'statsd', Mock())

    # Sanity check: Ensure the logout handler and url are set on the hub
    handlers = [handler for _, handler in authenticator.get_handlers(None)]
    assert any([h == SSOLogoutHandler for h in handlers])
    assert authenticator.logout_url('http://myhost') == 'http://myhost/logout'

    await logout_handler.get()
    # Enable after upgrade to oauthenticator==0.14.0
    # assert logout_handler.clear_login_cookie.called
    # logout_handler.clear_cookie.assert_called_once_with(STATE_COOKIE_NAME)
