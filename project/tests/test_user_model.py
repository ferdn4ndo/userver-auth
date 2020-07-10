import json
import unittest

from project.server import db
from project.server.models import User
from project.tests.base import BaseTestCase


class TestUserModel(BaseTestCase):
    system_name = 'testSystem'

    def test_encode_auth_token(self):
        user = User(
            username='joe@gmail.com',
            system_name=self.system_name,
            password='123456'
        )
        db.session.add(user)
        db.session.commit()
        auth_token = user.encode_auth_token()
        self.assertTrue(isinstance(auth_token, dict))
        self.assertIn('token', auth_token)
        self.assertIn('expires_at', auth_token)

    def test_decode_auth_token(self):
        user = User(
            username='joe@gmail.com',
            system_name=self.system_name,
            password='123456'
        )
        db.session.add(user)
        db.session.commit()

        auth_token = user.encode_auth_token()
        self.assertTrue(isinstance(auth_token, dict))
        self.assertIn('token', auth_token)
        self.assertIn('expires_at', auth_token)

        decoded_token = User.decode_auth_token(auth_token['token'])
        self.assertEqual(decoded_token['sub'], str(user.uuid))


if __name__ == '__main__':
    unittest.main()
