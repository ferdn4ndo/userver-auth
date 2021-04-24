import datetime
import os

from dateutil import tz
from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db, limiter
from project.server.auth.errors import BadRequestError, ConflictError, UnauthorizedError
from project.server.models import User, BlacklistToken, System

auth_blueprint = Blueprint('auth', __name__)


def get_authorization_token(request, word='Bearer') -> str:
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        raise UnauthorizedError('No authorization header provided.')

    header_parts = auth_header.split(" ")
    if len(header_parts) != 2:
        raise UnauthorizedError('Malformed authorization header.')

    if str(header_parts[0]).upper() != word.upper():
        raise UnauthorizedError('Authorization header must use {} word before the token.'.format(word))

    return str(header_parts[1])


def get_user_from_token(auth_token) -> User:
    user_token = User.decode_auth_token(auth_token)
    user = User.query.filter_by(uuid=user_token['sub']).first()
    if not user:
        blacklist_token = BlacklistToken(token=auth_token)
        db.session.add(blacklist_token)
        db.session.commit()
        raise UnauthorizedError('User is unknown.')

    return user


def check_request_body_keys(request, required_keys):
    if request.json is None or any([key not in request.json for key in required_keys]):
        fields_str = "['{}']".format("', '".join(required_keys))
        raise BadRequestError("The fields {} are required (in JSON format)!".format(fields_str))


def create_system(data) -> System:
    system = System.query.filter_by(name=data['name']).first()
    if system is not None:
        raise ConflictError('System already exists.')

    system_token = data['token'] if 'token' in data else None
    system = System(name=data['name'], token=system_token)
    db.session.add(system)
    db.session.commit()
    return system


class SystemAPI(MethodView):
    """
    System Creation Resource
    """
    @limiter.limit("100 per day")
    def post(self):
        try:
            if get_authorization_token(request, 'Token') != os.environ['SYSTEM_CREATION_TOKEN']:
                raise UnauthorizedError('Invalid system creation authorization token')
            check_request_body_keys(request, ['name'])
            system = create_system(request.json)
            response = {
                'id': system.id,
                'name': system.name,
                'token': system.token,
                'created_at': system.created_at.isoformat(),
            }

            return make_response(jsonify(response), 201)

        except BadRequestError as e:
            return make_response(jsonify({'message': str(e)})), 400
        except UnauthorizedError as e:
            return make_response(jsonify({'message': str(e)})), 401
        except ConflictError as e:
            return make_response(jsonify({'message': str(e)})), 409


class RegisterAPI(MethodView):
    """
    User Registration Resource
    """
    @limiter.limit("1000 per hour")
    def post(self):
        try:
            check_request_body_keys(request, ['username', 'system_name', 'system_token', 'password'])
            post_data = request.json

            system = System.query.filter_by(name=post_data['system_name']).first()
            if system is None or system.token != post_data['system_token']:
                raise UnauthorizedError("Invalid system/token pair.")

            user = User.query.filter_by(username=post_data['username'], system_name=post_data['system_name']).first()
            if user is not None:
                raise ConflictError("Username '{}' already registered for system '{}'!".format(
                    post_data['username'], post_data['system_name']
                ))

        except BadRequestError as e:
            return make_response(jsonify({'message': str(e)})), 400
        except UnauthorizedError as e:
            return make_response(jsonify({'message': str(e)})), 401
        except ConflictError as e:
            return make_response(jsonify({'message': str(e)})), 409

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

        is_admin = post_data['is_admin'] if 'is_admin' in post_data else False
        user = User(
            username=post_data['username'],
            system_name=post_data['system_name'],
            password=post_data['password'],
            is_admin=is_admin,
        )
        db.session.add(user)
        db.session.commit()

        auth_token = user.encode_auth_token()
        response = {
            'username': user.username,
            'system_name': user.system_name,
            'is_admin': user.is_admin,
            'auth': auth_token,
        }

        return make_response(jsonify(response), 201)


class LoginAPI(MethodView):
    """
    User Login Resource
    """
    @limiter.limit("1000 per hour")
    def post(self):
        try:
            check_request_body_keys(request, ['username', 'system_name', 'system_token', 'password'])
            post_data = request.json

            system = System.query.filter_by(name=post_data['system_name']).first()
            if system is None or system.token != post_data['system_token']:
                raise UnauthorizedError("Invalid system/token pair.")

            user = User.query.filter_by(username=post_data['username'], system_name=post_data['system_name']).first()
            if not user or not bcrypt.check_password_hash(user.password, post_data['password']):
                raise UnauthorizedError('Incorrect user credentials.')

            access_token = user.encode_auth_token('access')
            refresh_token = user.encode_auth_token('refresh')
            return make_response(jsonify({
                'access_token': access_token['token'],
                'access_token_exp': access_token['expires_at'],
                'refresh_token': refresh_token['token'],
                'refresh_token_exp': refresh_token['expires_at'],
            }), 200)
        except BadRequestError as e:
            return make_response(jsonify({'message': str(e)})), 400
        except UnauthorizedError as e:
            return make_response(jsonify({'message': str(e)})), 401


class RefreshTokenAPI(MethodView):
    """
    Used to refresh the AccessToken using a valid RefreshToken
    """
    @limiter.limit("1000 per hour")
    def post(self):
        try:
            token = get_authorization_token(request)
            user = get_user_from_token(token)
            new_auth_token = user.encode_auth_token()
            return make_response(jsonify(new_auth_token), 200)

        except PermissionError as e:
            return make_response(jsonify({'message': str(e)})), 401


class MeAPI(MethodView):
    """
    User status resource (kinda health-check also)
    """

    @limiter.limit("10000 per hour")
    def get(self):
        try:
            auth_token = get_authorization_token(request=request)
            user = get_user_from_token(auth_token=auth_token)
        except PermissionError as e:
            return make_response(jsonify({'message': str(e)})), 401

        user.update_last_activity()
        response_dict = {
            'uuid': user.uuid,
            'system_name': user.system_name,
            'username': user.username,
            'registered_at': user.registered_at.isoformat(),
            'last_activity_at': user.last_activity_at.isoformat(),
            'is_admin': user.is_admin,
        }
        return make_response(jsonify(response_dict), 200)


class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    @limiter.limit("1000 per hour")
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
