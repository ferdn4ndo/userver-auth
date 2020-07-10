import datetime
import os

from dateutil import tz
from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db, limiter
from project.server.models import User, BlacklistToken, System

auth_blueprint = Blueprint('auth', __name__)


class SystemAPI(MethodView):
    """
    System Creation Resource
    """
    @limiter.limit("100 per day")
    def post(self):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return make_response(jsonify({
                'message': 'No authorization header provided.'
            }), 401)

        try:
            auth_type, auth_token = auth_header.split()
            if str(auth_type).lower() != "token" or auth_token != os.environ['SYSTEM_CREATION_TOKEN']:
                return make_response(jsonify({
                    'message': 'Invalid authorization token.'
                })), 401
        except ValueError:
            return make_response(jsonify({
                'message': 'Malformed token authorization header.'
            })), 401

        required_keys = ['name']
        if request.json is None or any([key not in request.json for key in required_keys]):
            return make_response(jsonify({
                'message': "The fields ['{}'] are required (in JSON format)!".format("', '".join(required_keys))
            }), 400)
        post_data = request.json

        system = System.query.filter_by(name=post_data['name']).first()
        if system is not None:
            return make_response(jsonify({
                'message': 'System already exists.'
            })), 409

        system = System(name=post_data['name'])
        db.session.add(system)
        db.session.commit()

        response = {
            'id': system.id,
            'name': system.name,
            'token': system.token,
            'created_at': system.created_at.isoformat(),
        }

        return make_response(jsonify(response), 201)


class RegisterAPI(MethodView):
    """
    User Registration Resource
    """
    @limiter.limit("100 per day")
    def post(self):
        required_keys = ['username', 'system_name', 'system_token', 'password']
        if request.json is None or any([key not in request.json for key in required_keys]):
            return make_response(jsonify({
                'message': "The fields ['{}'] are required (in JSON format)!".format("', '".join(required_keys))
            }), 400)

        post_data = request.json
        system = System.query.filter_by(name=post_data['system_name']).first()
        if system is None or system.token != post_data['system_token']:
            return make_response(jsonify({
                'message': "Invalid system/token pair."
            }), 401)

        user = User.query.filter_by(username=post_data['username'], system_name=post_data['system_name']).first()
        if user is not None:
            return make_response(jsonify({
                'message': "Username '{}' already registered for system '{}'!".format(
                    post_data['username'], post_data['system_name']
                )
            }), 409)

        user = User(
            username=post_data['username'],
            system_name=post_data['system_name'],
            password=post_data['password']
        )
        db.session.add(user)
        db.session.commit()

        auth_token = user.encode_auth_token()
        return make_response(jsonify(auth_token), 201)


class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        required_keys = ['username', 'system_name', 'system_token', 'password']
        if request.json is None or any([key not in request.json for key in required_keys]):
            return make_response(jsonify({
                'message': "The fields ['{}'] are required (in JSON format)!".format("', '".join(required_keys))
            }), 400)

        post_data = request.json

        system = System.query.filter_by(name=post_data['system_name']).first()
        if system is None or system.token != post_data['system_token']:
            return make_response(jsonify({
                'message': "Invalid system/token pair."
            }), 401)

        user = User.query.filter_by(username=post_data['username'], system_name=post_data['system_name']).first()
        if not user or not bcrypt.check_password_hash(user.password, post_data['password']):
            return make_response(jsonify({
                'message': "Invalid user id/password pair."
            }), 401)

        auth_token = user.encode_auth_token()
        return make_response(jsonify(auth_token), 200)


class MeAPI(MethodView):
    """
    User status resource (kinda health-check also)
    """
    def get(self):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return make_response(jsonify({
                'message': 'No authorization header provided.'
            }), 401)

        try:
            auth_token = auth_header.split(" ")[1]
            user_token = User.decode_auth_token(auth_token)
        except IndexError:
            return make_response(jsonify({
                'message': 'Malformed Bearer authorization header.'
            })), 401
        except PermissionError as e:
            return make_response(jsonify({
                'message': str(e)
            })), 401

        user = User.query.filter_by(uuid=user_token['sub']).first()
        if not User:
            blacklist_token = BlacklistToken(token=auth_token)
            db.session.add(blacklist_token)
            db.session.commit()
            return make_response(jsonify({
                'message': 'User unknown.'
            })), 401

        user.update_last_activity()
        response_dict = {
            'uuid': user.uuid,
            'system_name': user.system_name,
            'username': user.username,
            'registered_at': user.registered_at.isoformat(),
            'last_activity_at': user.last_activity_at.isoformat(),
            'token': {
                'expires_at': datetime.datetime.fromtimestamp(user_token['exp'], tz=tz.UTC).isoformat(),
                'issued_at': datetime.datetime.fromtimestamp(user_token['iat'], tz=tz.UTC).isoformat(),
            },
        }
        return make_response(jsonify(response_dict), 200)


class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    def post(self):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return make_response(jsonify({
                'message': 'No authorization header provided.'
            }), 401)

        try:
            auth_token = auth_header.split(" ")[1]
            user_uuid = User.decode_auth_token(auth_token)['sub']
        except IndexError:
            return make_response(jsonify({
                'message': 'Malformed Bearer authorization header.'
            })), 401
        except PermissionError as e:
            return make_response(jsonify({
                'message': str(e)
            })), 401

        user = User.query.filter_by(uuid=user_uuid).first()
        if user:
            user.update_last_activity()

        blacklist_token = BlacklistToken(token=auth_token)
        db.session.add(blacklist_token)
        db.session.commit()
        return make_response('', 204)


# define the API resources
system_view = SystemAPI.as_view('system_api')
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
me_view = MeAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/auth/system',
    view_func=system_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/me',
    view_func=me_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
