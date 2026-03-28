import datetime
import os
import json
import unittest

from project.server import db
from project.server.models import User, BlacklistToken, System
from project.tests.base import BaseTestCase


def _api_datetime(dt):
    """Datetime strings returned by auth JSON responses (see project.server.auth.views)."""
    return dt.isoformat('T', 'milliseconds') + 'Z'


class TestAuthBlueprint(BaseTestCase):
    DEFAULT_SYSTEM_NAME = 'testSystem'
    DEFAULT_SYSTEM_CREATION_TOKEN = os.environ['SYSTEM_CREATION_TOKEN']
    DEFAULT_USER_EMAIL = 'joe@test.lan'
    DEFAULT_USER_PASSWORD = '123456@a'

    def create_system(self, **kwargs):
        return self.client.post(
            '/auth/system',
            data=json.dumps(kwargs),
            headers={
                'Authorization': 'Token {}'.format(self.DEFAULT_SYSTEM_CREATION_TOKEN)
            },
            content_type='application/json',
        )

    def get_system_token(self):
        system = System.query.filter_by(name=self.DEFAULT_SYSTEM_NAME).first()
        if system is None:
            system = System(name=self.DEFAULT_SYSTEM_NAME)
        db.session.add(system)
        db.session.commit()
        return system.token

    def register_user(self, **kwargs):
        return self.client.post(
            '/auth/register',
            data=json.dumps(kwargs),
            content_type='application/json',
        )

    def register_default_user(self):
        return self.register_user(
            username=self.DEFAULT_USER_EMAIL,
            system_name=self.DEFAULT_SYSTEM_NAME,
            system_token=self.get_system_token(),
            password=self.DEFAULT_USER_PASSWORD
        )

    def login_user(self, **kwargs):
        return self.client.post(
            '/auth/login',
            data=json.dumps(kwargs),
            content_type='application/json',
        )

    def login_default_user(self):
        return self.login_user(
            username=self.DEFAULT_USER_EMAIL,
            system_name=self.DEFAULT_SYSTEM_NAME,
            system_token=self.get_system_token(),
            password=self.DEFAULT_USER_PASSWORD
        )

    def get_me_response(self, token=None):
        return self.client.get(
            '/auth/me',
            headers={
                'Authorization': 'Bearer {}'.format(token)
            },
            content_type='application/json',
        )

    def patch_system_token(self, system_name, **kwargs):
        return self.client.patch(
            '/auth/systems/{}/token'.format(system_name),
            data=json.dumps(kwargs),
            content_type='application/json',
        )

    def patch_user_password(self, access_token, **kwargs):
        return self.client.patch(
            '/auth/me/password',
            data=json.dumps(kwargs),
            headers={
                'Authorization': 'Bearer {}'.format(access_token)
            },
            content_type='application/json',
        )

    def blacklist_token(self, token):
        blacklist_token = BlacklistToken(token=token)
        db.session.add(blacklist_token)
        db.session.commit()
        return blacklist_token

    def test_system_create_successful(self):
        """ Test for a successful system creation """
        with self.client:
            response = self.create_system(name=self.DEFAULT_SYSTEM_NAME)
            self.assertEqual(response.status_code, 201)
            self.assertEqual(response.content_type, 'application/json')

            data = json.loads(response.data.decode())
            self.assertIn('id', data)
            system = System.query.filter_by(id=data['id']).first()
            self.assertIn('name', data)
            self.assertEqual(data['name'], system.name)
            self.assertIn('token', data)
            self.assertEqual(data['token'], system.token)
            self.assertIn('created_at', data)
            self.assertEqual(data['created_at'], _api_datetime(system.created_at))

    def test_system_create_malformed_bearer_token(self):
        """ Test for a system creation with malformed token"""
        with self.client:
            response = self.client.post(
                '/auth/system',
                headers={
                    'Authorization': 'Bla'
                }
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_system_create_no_auth_header(self):
        """ Test for a system creation with no authorization header"""
        with self.client:
            response = self.client.post(
                '/auth/system',
                headers={}
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_system_create_invalid_token(self):
        """ Test for a system creation with an invalid token"""
        with self.client:
            response = self.client.post(
                '/auth/system',
                headers={
                    'Authorization': 'Token my_precious'
                }
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_register_successful(self):
        """ Test for user successful registration """
        with self.client:
            response = self.register_default_user()
            self.assertEqual(response.status_code, 201)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertTrue('auth' in data)
            self.assertTrue('access_token' in data['auth'])
            self.assertTrue('access_token_exp' in data['auth'])
            self.assertTrue('refresh_token' in data['auth'])
            self.assertTrue('refresh_token_exp' in data['auth'])
            self.assertTrue('is_admin' in data)
            self.assertTrue('system_name' in data)
            self.assertEqual(self.DEFAULT_SYSTEM_NAME, data['system_name'])
            self.assertTrue('username' in data)
            self.assertEqual(self.DEFAULT_USER_EMAIL, data['username'])

    def test_user_register_missing_field(self):
        """ Test registration with a missing field """
        user = User(
            username=self.DEFAULT_USER_EMAIL,
            system_name=self.DEFAULT_SYSTEM_NAME,
            password='test'
        )
        db.session.add(user)
        db.session.commit()
        with self.client:
            response = self.register_user(
                username=self.DEFAULT_USER_EMAIL,
                system_name=self.DEFAULT_SYSTEM_NAME,
                system_token=self.get_system_token(),
            )
            self.assertEqual(response.status_code, 400)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertTrue('message' in data)

    def test_user_register_wrong_system_token(self):
        """ Test registration with an invalid system token """
        with self.client:
            response = self.register_user(
                username=self.DEFAULT_USER_EMAIL,
                system_name=self.DEFAULT_SYSTEM_NAME,
                system_token='my_precious',
                password=self.DEFAULT_USER_PASSWORD
            )
            self.assertEqual(response.status_code, 401)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertTrue('message' in data)

    def test_user_register_already_registered(self):
        """ Test registration with already registered user """
        user = User(
            username=self.DEFAULT_USER_EMAIL,
            system_name=self.DEFAULT_SYSTEM_NAME,
            password='test'
        )
        db.session.add(user)
        db.session.commit()
        with self.client:
            response = self.register_user(
                username=self.DEFAULT_USER_EMAIL,
                system_name=self.DEFAULT_SYSTEM_NAME,
                system_token=self.get_system_token(),
                password=self.DEFAULT_USER_PASSWORD
            )
            data = json.loads(response.data.decode())
            self.assertEqual(response.status_code, 409)
            self.assertTrue(response.content_type == 'application/json')
            self.assertTrue('message' in data)

    def test_user_login_successful(self):
        """ Test for login of registered-user login """
        with self.client:
            # user registration
            resp_register = self.register_default_user()
            self.assertEqual(resp_register.status_code, 201)
            self.assertTrue(resp_register.content_type == 'application/json')

            data_register = json.loads(resp_register.data.decode())
            self.assertIn('auth', data_register)
            self.assertIn('access_token', data_register['auth'])
            self.assertIn('access_token_exp', data_register['auth'])
            self.assertIn('refresh_token', data_register['auth'])
            self.assertIn('refresh_token_exp', data_register['auth'])
            self.assertIn('is_admin', data_register)
            self.assertIn('system_name', data_register)
            self.assertIn('username', data_register)

            # registered user login
            response = self.get_me_response(token=data_register['auth']['access_token'])
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertIn('uuid', data)
            user = User.query.filter_by(uuid=data['uuid']).first()
            if user.last_activity_at is not None:
                self.assertIn('last_activity_at', data)
                self.assertEqual(data['last_activity_at'], _api_datetime(user.last_activity_at))
            self.assertIn('registered_at', data)
            self.assertEqual(data['registered_at'], _api_datetime(user.registered_at))
            self.assertIn('system_name', data)
            self.assertEqual(user.system_name, data['system_name'])
            self.assertIn('username', data)
            self.assertEqual(user.username, data['username'])

    def test_user_login_not_registered(self):
        """ Test for login of non-registered user """
        with self.client:
            response = self.login_default_user()
            self.assertEqual(response.status_code, 401)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertTrue('message' in data)

    def test_user_login_wrong_password(self):
        """ Test for login of wrong password user """
        with self.client:
            self.register_default_user()

            response = self.login_user(
                username=self.DEFAULT_USER_EMAIL,
                system_name=self.DEFAULT_SYSTEM_NAME,
                system_token=self.get_system_token(),
                password='my_precious'
            )
            self.assertEqual(response.status_code, 401)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertTrue('message' in data)

    def test_user_login_wrong_system_token(self):
        """ Test for login of wrong password user """
        with self.client:
            self.register_default_user()

            response = self.login_user(
                username=self.DEFAULT_USER_EMAIL,
                system_name=self.DEFAULT_SYSTEM_NAME,
                system_token='my_precious',
                password=self.DEFAULT_USER_PASSWORD
            )
            self.assertEqual(response.status_code, 401)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertTrue('message' in data)

    def test_user_status_successful(self):
        """ Test for user status """
        with self.client:
            resp_register = self.register_default_user()
            response = self.get_me_response(token=json.loads(resp_register.data.decode())['auth']['access_token'])
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content_type, 'application/json')

            data = json.loads(response.data.decode())
            self.assertIn('uuid', data)
            user = User.query.filter_by(uuid=data['uuid']).first()
            self.assertIn('system_name', data)
            self.assertEqual(data['system_name'], user.system_name)
            self.assertIn('username', data)
            self.assertEqual(data['username'], user.username)
            self.assertIn('registered_at', data)
            self.assertEqual(data['registered_at'], _api_datetime(user.registered_at))
            if user.last_activity_at is not None:
                self.assertIn('last_activity_at', data)
                self.assertEqual(data['last_activity_at'], _api_datetime(user.last_activity_at))

    def test_user_status_malformed_bearer_token(self):
        """ Test for user status with malformed bearer token"""
        with self.client:
            resp_register = self.register_default_user()
            response = self.client.get(
                '/auth/me',
                headers={
                    'Authorization': 'Bearer'
                }
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_status_no_auth_header(self):
        """ Test for user status with no authorization header"""
        with self.client:
            resp_register = self.register_default_user()
            response = self.client.get(
                '/auth/me',
                headers={}
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_status_invalid_token(self):
        """ Test for user status with an invalid bearer token"""
        with self.client:
            resp_register = self.register_default_user()
            response = self.client.get(
                '/auth/me',
                headers={
                    'Authorization': 'Bearer my_precious'
                }
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_status_blacklisted_token(self):
        """ Test for user status with an invalid bearer token"""
        with self.client:
            resp_register = self.register_default_user()
            self.assertEqual(resp_register.status_code, 201)

            resp_login = self.login_default_user()
            self.assertEqual(resp_login.status_code, 200)
            self.assertEqual(resp_login.content_type, 'application/json')

            token = json.loads(resp_login.data.decode())['access_token']
            self.blacklist_token(token)
            response = self.client.get(
                '/auth/me',
                headers={
                    'Authorization': 'Bearer ' + token
                }
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_refresh_token_successful(self):
        """ Test for user refresh token """
        with self.client:
            resp_register = self.register_default_user()
            refresh_token = json.loads(resp_register.data.decode())['auth']['refresh_token']
            response = self.client.post(
                '/auth/refresh',
                headers={
                    'Authorization': 'Bearer {}'.format(refresh_token)
                },
                content_type='application/json',
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content_type, 'application/json')

            data = json.loads(response.data.decode())
            self.assertIn('access_token', data)
            self.assertIn('access_token_exp', data)
            self.assertIn('refresh_token', data)
            self.assertIn('refresh_token_exp', data)

    def test_user_refresh_token_malformed_bearer_token(self):
        """ Test for user refresh token with malformed bearer token"""
        with self.client:
            resp_register = self.register_default_user()
            response = self.client.post(
                '/auth/refresh',
                headers={
                    'Authorization': 'Bearer'
                }
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_refresh_token_no_auth_header(self):
        """ Test for user refresh token with no authorization header"""
        with self.client:
            resp_register = self.register_default_user()
            response = self.client.post(
                '/auth/refresh',
                headers={}
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_refresh_token_invalid_token(self):
        """ Test for user refresh token with an invalid bearer token"""
        with self.client:
            resp_register = self.register_default_user()
            response = self.client.post(
                '/auth/refresh',
                headers={
                    'Authorization': 'Bearer my_precious'
                }
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_refersh_token_blacklisted_token(self):
        """ Test for user status with an invalid bearer token"""
        with self.client:
            resp_register = self.register_default_user()
            self.assertEqual(resp_register.status_code, 201)

            token = json.loads(resp_register.data.decode())['auth']['refresh_token']
            self.blacklist_token(token)
            response = self.client.post(
                '/auth/refresh',
                headers={
                    'Authorization': 'Bearer ' + token
                }
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_logout_successful(self):
        """ Test for logout before token expires """
        with self.client:
            resp_register = self.register_default_user()
            self.assertEqual(resp_register.status_code, 201)

            resp_login = self.login_default_user()
            self.assertEqual(resp_login.status_code, 200)
            self.assertEqual(resp_login.content_type, 'application/json')

            response = self.client.post(
                '/auth/logout',
                headers={
                    'Authorization': 'Bearer ' + json.loads(resp_login.data.decode())['access_token']
                }
            )
            self.assertEqual(response.status_code, 204)
            self.assertEqual(response.data.decode(), '')

    def test_user_logout_malformed_bearer_token(self):
        """ Test for user logout with malformed bearer token"""
        with self.client:
            resp_register = self.register_default_user()
            response = self.client.post(
                '/auth/logout',
                headers={
                    'Authorization': 'Bearer'
                }
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_logout_no_auth_header(self):
        """ Test for user logout with no authorization header"""
        with self.client:
            resp_register = self.register_default_user()
            response = self.client.post(
                '/auth/logout',
                headers={}
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_logout_invalid_token(self):
        """ Test for user logout with an invalid bearer token"""
        with self.client:
            resp_register = self.register_default_user()
            response = self.client.post(
                '/auth/logout',
                headers={
                    'Authorization': 'Bearer my_precious'
                }
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_user_logout_blacklisted_token(self):
        """ Test for user logout with an invalid bearer token"""
        with self.client:
            resp_register = self.register_default_user()
            self.assertEqual(resp_register.status_code, 201)

            resp_login = self.login_default_user()
            self.assertEqual(resp_login.status_code, 200)
            self.assertEqual(resp_login.content_type, 'application/json')

            token = json.loads(resp_login.data.decode())['access_token']
            self.blacklist_token(token)
            response = self.client.post(
                '/auth/logout',
                headers={
                    'Authorization': 'Bearer ' + token
                }
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.content_type, 'application/json')
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_patch_system_token_success_explicit_new(self):
        """Rotate system token when current token and new token are provided."""
        with self.client:
            self.create_system(name=self.DEFAULT_SYSTEM_NAME)
            old_token = self.get_system_token()
            reg = self.register_default_user()
            self.assertEqual(reg.status_code, 201)

            new_token = 'explicit-new-token-value-unique-12345'
            response = self.patch_system_token(
                self.DEFAULT_SYSTEM_NAME,
                current_system_token=old_token,
                new_system_token=new_token,
            )
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data.decode())
            self.assertEqual(data['name'], self.DEFAULT_SYSTEM_NAME)
            self.assertEqual(data['token'], new_token)

            system = System.query.filter_by(name=self.DEFAULT_SYSTEM_NAME).first()
            self.assertEqual(system.token, new_token)

            login_old = self.login_user(
                username=self.DEFAULT_USER_EMAIL,
                system_name=self.DEFAULT_SYSTEM_NAME,
                system_token=old_token,
                password=self.DEFAULT_USER_PASSWORD,
            )
            self.assertEqual(login_old.status_code, 401)

            login_new = self.login_user(
                username=self.DEFAULT_USER_EMAIL,
                system_name=self.DEFAULT_SYSTEM_NAME,
                system_token=new_token,
                password=self.DEFAULT_USER_PASSWORD,
            )
            self.assertEqual(login_new.status_code, 200)

    def test_patch_system_token_success_auto_generated(self):
        """Omitting new_system_token generates a new token server-side."""
        with self.client:
            self.create_system(name=self.DEFAULT_SYSTEM_NAME)
            old_token = self.get_system_token()
            response = self.patch_system_token(
                self.DEFAULT_SYSTEM_NAME,
                current_system_token=old_token,
            )
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data.decode())
            self.assertIn('token', data)
            self.assertNotEqual(data['token'], old_token)
            self.assertGreater(len(data['token']), 10)

    def test_patch_system_token_system_not_found(self):
        with self.client:
            response = self.patch_system_token(
                'nonexistent',
                current_system_token='any',
            )
            self.assertEqual(response.status_code, 404)

    def test_patch_system_token_wrong_current(self):
        with self.client:
            self.create_system(name=self.DEFAULT_SYSTEM_NAME)
            response = self.patch_system_token(
                self.DEFAULT_SYSTEM_NAME,
                current_system_token='wrong-token',
                new_system_token='new-one',
            )
            self.assertEqual(response.status_code, 401)
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

    def test_patch_system_token_missing_current(self):
        with self.client:
            self.create_system(name=self.DEFAULT_SYSTEM_NAME)
            response = self.patch_system_token(
                self.DEFAULT_SYSTEM_NAME,
                new_system_token='only-new',
            )
            self.assertEqual(response.status_code, 400)

    def test_patch_system_token_conflict(self):
        with self.client:
            self.create_system(name=self.DEFAULT_SYSTEM_NAME)
            self.create_system(name='otherSystem')
            sys_a_token = System.query.filter_by(name=self.DEFAULT_SYSTEM_NAME).first().token
            sys_b_token = System.query.filter_by(name='otherSystem').first().token
            response = self.patch_system_token(
                self.DEFAULT_SYSTEM_NAME,
                current_system_token=sys_a_token,
                new_system_token=sys_b_token,
            )
            self.assertEqual(response.status_code, 409)

    def test_patch_user_password_success(self):
        with self.client:
            resp_register = self.register_default_user()
            self.assertEqual(resp_register.status_code, 201)
            access = json.loads(resp_register.data.decode())['auth']['access_token']
            new_password = 'new-secure-pass-9'

            response = self.patch_user_password(
                access,
                current_password=self.DEFAULT_USER_PASSWORD,
                new_password=new_password,
            )
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data.decode())
            self.assertIn('message', data)

            login_old = self.login_default_user()
            self.assertEqual(login_old.status_code, 401)

            login_new = self.login_user(
                username=self.DEFAULT_USER_EMAIL,
                system_name=self.DEFAULT_SYSTEM_NAME,
                system_token=self.get_system_token(),
                password=new_password,
            )
            self.assertEqual(login_new.status_code, 200)

    def test_patch_user_password_wrong_current(self):
        with self.client:
            resp_register = self.register_default_user()
            access = json.loads(resp_register.data.decode())['auth']['access_token']
            response = self.patch_user_password(
                access,
                current_password='not-the-password',
                new_password='something-else',
            )
            self.assertEqual(response.status_code, 401)

    def test_patch_user_password_empty_new(self):
        with self.client:
            resp_register = self.register_default_user()
            access = json.loads(resp_register.data.decode())['auth']['access_token']
            response = self.patch_user_password(
                access,
                current_password=self.DEFAULT_USER_PASSWORD,
                new_password='',
            )
            self.assertEqual(response.status_code, 400)

    def test_patch_user_password_missing_fields(self):
        with self.client:
            resp_register = self.register_default_user()
            access = json.loads(resp_register.data.decode())['auth']['access_token']
            response = self.patch_user_password(
                access,
                current_password=self.DEFAULT_USER_PASSWORD,
            )
            self.assertEqual(response.status_code, 400)

    def test_patch_user_password_no_auth(self):
        with self.client:
            response = self.client.patch(
                '/auth/me/password',
                data=json.dumps({
                    'current_password': self.DEFAULT_USER_PASSWORD,
                    'new_password': 'x',
                }),
                content_type='application/json',
            )
            self.assertEqual(response.status_code, 401)

    def test_patch_user_password_invalid_token(self):
        with self.client:
            response = self.patch_user_password(
                'invalid.jwt.here',
                current_password=self.DEFAULT_USER_PASSWORD,
                new_password='x',
            )
            self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()
