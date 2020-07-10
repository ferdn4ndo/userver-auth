import os

from flask import Flask, jsonify, make_response
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__, static_url_path='/docs', static_folder='docs')
CORS(app)

app_settings = os.getenv('APP_SETTINGS', 'project.server.config.DevelopmentConfig')
app.config.from_object(app_settings)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=app.config['THROTTLING_LIMITS']
)

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

from project.server.auth.views import auth_blueprint
app.register_blueprint(auth_blueprint)


from project.server.docs.views import docs_blueprint
app.register_blueprint(docs_blueprint)


@app.errorhandler(429)
def ratelimit_handler(e):
    return make_response(jsonify({
        'message': "Ratelimit exceeded: {}. Please, calm down!".format(e.description)
    }), 420)
