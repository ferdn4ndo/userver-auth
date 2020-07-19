# project/server/models.py


import datetime
import os
import secrets

import jwt
import uuid

from project.server import app, db, bcrypt
from sqlalchemy.dialects.postgresql import UUID


class System(db.Model):
    """
    System model for storing system tokens used to select the login/registration destination
    """

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(500), unique=True, nullable=False)
    token = db.Column(db.String(500), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)

    def __init__(self, name):
        self.name = name
        self.token = secrets.token_urlsafe(32)
        self.created_at = datetime.datetime.now()

    def __repr__(self):
        return '<system id={} name={} token={}>'.format(self.id, self.name, self.token)


class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = "users"

    uuid = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    system_name = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_at = db.Column(db.DateTime, nullable=False)
    last_activity_at = db.Column(db.DateTime, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, system_name, username, password, is_admin=False):
        self.system_name = system_name
        self.username = username
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.registered_at = datetime.datetime.now()
        self.last_activity_at = datetime.datetime.now()
        self.is_admin = is_admin

    def update_last_activity(self):
        self.last_activity_at = datetime.datetime.now()

    def encode_auth_token(self):
        """
        Generates the Auth Token
        :return: string
        """
        exp_utc = datetime.datetime.utcnow() + datetime.timedelta(seconds=int(os.environ['JWT_EXP_DELTA_SECS']))
        payload = {
            'exp': exp_utc,
            'iat': datetime.datetime.utcnow(),
            'sub': str(self.uuid)
        }
        token = jwt.encode(
            payload,
            app.config.get('SECRET_KEY'),
            algorithm='HS256'
        )

        self.update_last_activity()

        return {
            'token': token.decode(),
            'expires_at': exp_utc.isoformat()
        }


    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                raise PermissionError('Token blacklisted. Please log in again.')
            else:
                return payload
        except jwt.ExpiredSignatureError:
            raise PermissionError('Signature expired. Please log in again.')
        except jwt.InvalidTokenError:
            raise PermissionError('Invalid token. Please log in again.')


class BlacklistToken(db.Model):
    """
    Token Model for storing blacklisted JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_at = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_at = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False