import os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

basedir = os.path.abspath(os.path.dirname(__file__))
postgres_base_uri = 'postgresql://{}:{}@{}/'.format(
    os.environ['POSTGRES_USER'],
    os.environ['POSTGRES_PASS'],
    os.environ['POSTGRES_HOST'],
)


class BaseConfig:
    """Base configuration."""
    SECRET_KEY = os.environ['FLASK_SECRET_KEY']
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    THROTTLING_LIMITS = ["10000 per day", "100 per hour"]


class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    SECRET_KEY = os.environ['FLASK_SECRET_KEY']
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_base_uri + os.environ['POSTGRES_DB']


class TestingConfig(BaseConfig):
    """Testing configuration."""
    SECRET_KEY = os.environ['FLASK_SECRET_KEY']
    DEBUG = True
    TESTING = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_base_uri + os.environ['POSTGRES_DB_TEST']
    PRESERVE_CONTEXT_ON_EXCEPTION = False


class ProductionConfig(BaseConfig):
    """Production configuration."""
    SECRET_KEY = os.environ['FLASK_SECRET_KEY']
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = postgres_base_uri + os.environ['POSTGRES_DB']
    THROTTLING_LIMITS = ["1000 per day", "10 per minute"]
