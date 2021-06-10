import os

from datetime import datetime
from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db, limiter
from project.server.auth.errors import BadRequestError, ConflictError, UnauthorizedError
from project.server.models import User, BlacklistToken, System

auth_blueprint = Blueprint('auth', __name__)


def parse_token_data(auth_token, token_type="access"):
    token_data = User.decode_auth_token(auth_token, token_type)

    return {
        "issued_at": datetime.utcfromtimestamp(token_data['iat']).isoformat('T', 'milliseconds')+ 'Z',
        "expires_at": datetime.utcfromtimestamp(token_data['exp']).isoformat('T', 'milliseconds')+ 'Z',
    }


def get_authorization_token(request_obj, word='Bearer') -> str:
    auth_header = request_obj.headers.get('Authorization')
    if not auth_header:
        raise UnauthorizedError('No authorization header provided.')

    header_parts = auth_header.split(" ")
    if len(header_parts) != 2:
        raise UnauthorizedError('Malformed authorization header.')

    if str(header_parts[0]).upper() != word.upper():
        raise UnauthorizedError('Authorization header must use {} word before the token.'.format(word))

    return str(header_parts[1])


def get_user_from_token(auth_token, token_type="access") -> User:
    user_token = User.decode_auth_token(auth_token, token_type)
    user = User.query.filter_by(uuid=user_token['sub']).first()
    if not user:
        blacklist_token = BlacklistToken(token=auth_token)
        db.session.add(blacklist_token)
        db.session.commit()
        raise UnauthorizedError('User is unknown.')

    return user


def check_request_body_keys(data, required_keys):
    if data is None or any([key not in data for key in required_keys]):
        fields_str = "['{}']".format("', '".join(required_keys))
        raise BadRequestError("The fields {} are required (in JSON format)!".format(fields_str))


def check_system_credentials(data):
    if 'system_name' not in data or 'system_token' not in data:
        raise UnauthorizedError("System name/token required.")

    system = System.query.filter_by(name=data['system_name']).first()
    if system is None or system.token != data['system_token']:
        raise UnauthorizedError("Invalid system name/token pair.")


def create_system(data) -> System:
    system = System.query.filter_by(name=data['name']).first()
    if system is not None:
        raise ConflictError('System already exists.')

    system_token = data['token'] if 'token' in data else None
    if system_token and System.query.filter_by(token=data['token']).first() is not None:
        raise ConflictError('Token already in use.')

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
            check_request_body_keys(request.json, ['name'])
            system = create_system(request.json)
            response = {
                'id': system.id,
                'name': system.name,
                'token': system.token,
                'created_at': system.created_at.isoformat('T', 'milliseconds')+ 'Z',
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
            check_request_body_keys(request.json, ['username', 'system_name', 'system_token', 'password'])
            check_system_credentials(request.json)
            post_data = request.json

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
            check_request_body_keys(request.json, ['username', 'system_name', 'system_token', 'password'])
            post_data = request.json

            system = System.query.filter_by(name=post_data['system_name']).first()
            if system is None or system.token != post_data['system_token']:
                raise UnauthorizedError("Invalid system/token pair.")

            user = User.query.filter_by(username=post_data['username'], system_name=post_data['system_name']).first()
            if not user or not bcrypt.check_password_hash(user.password, post_data['password']):
                raise UnauthorizedError('Incorrect user credentials.')

            return make_response(jsonify(user.encode_auth_token())), 200
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
            user = get_user_from_token(auth_token=token, token_type="refresh")
            new_auth_token = user.encode_auth_token()
            return make_response(jsonify(new_auth_token), 200)

        except UnauthorizedError as e:
            return make_response(jsonify({'message': str(e)})), 401


class MeAPI(MethodView):
    """
    User status resource (kinda health-check also)
    """
    @limiter.limit("10000 per hour")
    def get(self):
        try:
            auth_token = get_authorization_token(request)
            user = get_user_from_token(auth_token=auth_token)
            user.update_last_activity()
            response_dict = {
                'uuid': user.uuid,
                'system_name': user.system_name,
                'username': user.username,
                'registered_at': user.registered_at.isoformat('T', 'milliseconds')+ 'Z',
                'last_activity_at': user.last_activity_at.isoformat('T', 'milliseconds')+ 'Z',
                'is_admin': user.is_admin,
                'token': parse_token_data(auth_token),
            }
            return make_response(jsonify(response_dict), 200)

        except UnauthorizedError as e:
            return make_response(jsonify({'message': str(e)})), 401


class SystemUserAPI(MethodView):
    """
    Retrieve info about a user from a system
    """
    @limiter.limit("10000 per hour")
    def get(self, system_name, username):
        try:
            auth_token = get_authorization_token(request)
            logged_user = get_user_from_token(auth_token=auth_token)
            logged_user.update_last_activity()

            user = User.query.filter_by(system_name=system_name, username=username).first()
            if not user:
                return make_response(jsonify({
                    'message': 'Username {} not found for system {}!'.format(username, system_name)
                })), 404

            response_dict = {
                'uuid': user.uuid,
                'system_name': user.system_name,
                'username': user.username,
                'registered_at': user.registered_at.isoformat('T', 'milliseconds')+ 'Z',
                'last_activity_at': user.last_activity_at.isoformat('T', 'milliseconds')+ 'Z',
            }

            return make_response(jsonify(response_dict), 200)

        except UnauthorizedError as e:
            return make_response(jsonify({'message': str(e)})), 401


class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    @limiter.limit("1000 per hour")
    def post(self):
        try:
            auth_token = get_authorization_token(request)
            user = get_user_from_token(auth_token=auth_token)

            if user:
                user.update_last_activity()

            blacklist_token = BlacklistToken(token=auth_token)
            db.session.add(blacklist_token)
            db.session.commit()
            return make_response('', 204)

        except UnauthorizedError as e:
            return make_response(jsonify({'message': str(e)})), 401


# define the API resources
system_view = SystemAPI.as_view('system_api')
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
refresh_view = RefreshTokenAPI.as_view('refresh_api')
me_view = MeAPI.as_view('user_api')
system_user_view = SystemUserAPI.as_view('system_user_api')
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
    '/auth/refresh',
    view_func=refresh_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/me',
    view_func=me_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/systems/<system_name>/users/<username>',
    view_func=system_user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
