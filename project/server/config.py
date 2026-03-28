import os

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
    # Explicit default; override in subclasses. Use Redis in production (see .env.template).
    RATELIMIT_STORAGE_URI = 'memory://'


class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    SECRET_KEY = os.environ['FLASK_SECRET_KEY']
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_base_uri + os.environ['POSTGRES_DB']
    RATELIMIT_STORAGE_URI = (
        os.environ.get('RATELIMIT_STORAGE_URI')
        or os.environ.get('REDIS_URL')
        or 'memory://'
    )


class TestingConfig(BaseConfig):
    """Testing configuration."""
    SECRET_KEY = os.environ['FLASK_SECRET_KEY']
    DEBUG = True
    TESTING = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = postgres_base_uri + os.environ['POSTGRES_DB_TEST']
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    RATELIMIT_STORAGE_URI = 'memory://'


class ProductionConfig(BaseConfig):
    """Production configuration."""
    SECRET_KEY = os.environ['FLASK_SECRET_KEY']
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = postgres_base_uri + os.environ['POSTGRES_DB']
    THROTTLING_LIMITS = ["1000 per day", "10 per minute"]
    RATELIMIT_STORAGE_URI = (
        os.environ.get('RATELIMIT_STORAGE_URI')
        or os.environ.get('REDIS_URL')
        or 'memory://'
    )
