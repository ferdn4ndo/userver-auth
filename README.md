# uServer Auth

Authentication microservice based on [flask-jwt-auth](https://github.com/realpython/flask-jwt-auth).

It's part of the [uServer](https://github.com/users/ferdn4ndo/projects/1) stack project.

Check out the [blog post](https://realpython.com/blog/python/token-based-authentication-with-flask/) to understand the original project where this one originated.

## Prepare the environment

Copy `.env.template` to `.env` and edit it accordingly.

## Run the Application

```sh
docker-compose up --build
```

## Setup it (first run only)

Take a look at `setup.sh` and `setup.py` and adjust them accordingly (if needed). Then run:

```sh
docker exec -it userver-auth sh -c "./setup.sh"
```

Access the application at the address [http://localhost:5000/](http://localhost:5000/) or any other environment configuration you made.

## Endpoints

* **POST** `/auth/system`: to create a system
* **POST** `/auth/register`: to register a new user to a system
* **POST** `/auth/login`: to login a user from a system
* **POST** `/auth/refresh`: to refresh the JWT access token of a logged user
* **GET** `/auth/me`: to retrieve and check the user data/status
* **POST** `/auth/logout`: to logout a user

## Testing

### Without coverage:

```sh
docker exec -it userver-auth sh -c "python manage.py test"
```

### With coverage:

```sh
docker exec -it userver-auth sh -c "python manage.py cov"
```
