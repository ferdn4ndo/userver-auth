import json
import unittest

from project.server import db
from project.server.models import User
from project.tests.base import BaseTestCase


class TestUserModel(BaseTestCase):
    DEFAULT_SYSTEM_NAME = 'testSystem'
    DEFAULT_USER_EMAIL = 'joe@test.lan'
    DEFAULT_USER_PASSWORD = '123456@a'

    def test_encode_auth_token(self):
        user = User(
            username=self.DEFAULT_USER_EMAIL,
            system_name=self.DEFAULT_SYSTEM_NAME,
            password=self.DEFAULT_USER_PASSWORD
        )
        db.session.add(user)
        db.session.commit()
        auth_token = user.encode_auth_token()
        self.assertTrue(isinstance(auth_token, dict))
        self.assertIn('access_token', auth_token)
        self.assertIn('access_token_exp', auth_token)
        self.assertIn('refresh_token', auth_token)
        self.assertIn('refresh_token_exp', auth_token)

    def test_decode_auth_token(self):
        user = User(
            username=self.DEFAULT_USER_EMAIL,
            system_name=self.DEFAULT_SYSTEM_NAME,
            password=self.DEFAULT_USER_PASSWORD
        )
        db.session.add(user)
        db.session.commit()

        auth_token = user.encode_auth_token()
        self.assertTrue(isinstance(auth_token, dict))
        self.assertIn('access_token', auth_token)
        self.assertIn('access_token_exp', auth_token)
        self.assertIn('refresh_token', auth_token)
        self.assertIn('refresh_token_exp', auth_token)

        decoded_access_token = User.decode_auth_token(auth_token['access_token'], 'access')
        self.assertEqual(decoded_access_token['sub'], str(user.uuid))
        decoded_refresh_token = User.decode_auth_token(auth_token['refresh_token'], 'refresh')
        self.assertEqual(decoded_refresh_token['sub'], str(user.uuid))


if __name__ == '__main__':
    unittest.main()
