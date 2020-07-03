# project/tests/test_auth.py
import datetime
import time
import json
import unittest

from project.server import db
from project.server.models import User, BlacklistToken
from project.tests.base import BaseTestCase


class TestAuthBlueprint(BaseTestCase):
    system_name = list(User.systems_token_dict.keys())[0]
    system_token = User.systems_token_dict[system_name]

    def register_user(self, **kwargs):
        return self.client.post(
            '/auth/register',
            data=json.dumps(kwargs),
            content_type='application/json',
        )

    def register_default_user(self):
        return self.register_user(
            username='joe@gmail.com',
            system=self.system_name,
            system_token=self.system_token,
            password='123456'
        )

    def login_user(self, **kwargs):
        return self.client.post(
            '/auth/login',
            data=json.dumps(kwargs),
            content_type='application/json',
        )

    def login_default_user(self):
        return self.login_user(
            username='joe@gmail.com',
            system=self.system_name,
            system_token=self.system_token,
            password='123456'
        )

    def blacklist_token(self, token):
        blacklist_token = BlacklistToken(token=token)
        db.session.add(blacklist_token)
        db.session.commit()
        return blacklist_token

    def test_user_register_successful(self):
        """ Test for user successful registration """
        with self.client:
            response = self.register_default_user()
            self.assertEqual(response.status_code, 201)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertTrue('token' in data)
            self.assertTrue(data['token'])
            self.assertTrue('expires_at' in data)
            self.assertTrue(data['expires_at'])

    def test_user_register_missing_field(self):
        """ Test registration with a missing field"""
        user = User(
            username='joe@gmail.com',
            system=self.system_name,
            password='test'
        )
        db.session.add(user)
        db.session.commit()
        with self.client:
            response = self.register_user(
                username='joe@gmail.com',
                system=self.system_name,
                system_token=self.system_token,
            )
            self.assertEqual(response.status_code, 400)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertTrue('message' in data)

    def test_user_register_wrong_system_token(self):
        """ Test registration with an invalid system token"""
        with self.client:
            response = self.register_user(
                username='joe@gmail.com',
                system=self.system_name,
                system_token='my_precious',
                password='123456'
            )
            self.assertEqual(response.status_code, 401)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertTrue('message' in data)

    def test_user_register_already_registered(self):
        """ Test registration with already registered user"""
        user = User(
            username='joe@gmail.com',
            system=self.system_name,
            password='test'
        )
        db.session.add(user)
        db.session.commit()
        with self.client:
            response = self.register_user(
                username='joe@gmail.com',
                system=self.system_name,
                system_token=self.system_token,
                password='123456'
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
            self.assertTrue(data_register['token'])
            self.assertTrue(data_register['expires_at'])

            # registered user login
            response = self.login_default_user()
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertTrue('token' in data)
            self.assertTrue(data_register['token'])
            self.assertTrue('expires_at' in data)
            self.assertTrue(data_register['expires_at'])

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
                username='joe@gmail.com',
                system=self.system_name,
                system_token=self.system_token,
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
                username='joe@gmail.com',
                system=self.system_name,
                system_token='my_precious',
                password='123456'
            )
            self.assertEqual(response.status_code, 401)
            self.assertTrue(response.content_type == 'application/json')

            data = json.loads(response.data.decode())
            self.assertTrue('message' in data)

    def test_user_status_successful(self):
        """ Test for user status """
        with self.client:
            resp_register = self.register_default_user()
            response = self.client.get(
                '/auth/me',
                headers={
                    'Authorization': 'Bearer ' + json.loads(resp_register.data.decode())['token']
                }
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content_type, 'application/json')

            data = json.loads(response.data.decode())
            self.assertIn('uuid', data)
            user = User.query.filter_by(uuid=data['uuid']).first()
            self.assertIn('system', data)
            self.assertEqual(data['system'], user.system)
            self.assertIn('username', data)
            self.assertEqual(data['username'], user.username)
            self.assertIn('registered_at', data)
            self.assertEqual(
                data['registered_at'],
                datetime.datetime.strftime(user.registered_at, '%Y-%m-%d %H:%M:%S')
            )
            if user.last_activity_at is not None:
                self.assertIn('last_activity_at', data)
                self.assertEqual(
                    data['last_activity_at'],
                    datetime.datetime.strftime(user.last_activity_at, '%Y-%m-%d %H:%M:%S')
                )

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

            token = json.loads(resp_login.data.decode())['token']
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
                    'Authorization': 'Bearer ' + json.loads(resp_login.data.decode())['token']
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

            token = json.loads(resp_login.data.decode())['token']
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


if __name__ == '__main__':
    unittest.main()
