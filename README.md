# Authenticator

Authentication microserveice based on [flask-jwt-auth](https://github.com/realpython/flask-jwt-auth).

Check out the [blog post](https://realpython.com/blog/python/token-based-authentication-with-flask/) to understand the original project where this one originated.


### Prepare the environment

Copy `.env.template` to `.env` and edit it accordingly.

### Run the Application

```sh
docker-compose up --build
```

### Setup it (first run only)

Take a look at `setup.sh` and adjust it accordingly if needed, then run:

```sh
docker exec -it authenticator sh -c "./setup.sh"
```


Access the application at the address [http://localhost:5000/](http://localhost:5000/) or any other environment configuration you made.

### Testing

Without coverage:

```sh
docker exec -it authenticator sh -c "python manage.py test"
```

With coverage:

```sh
docker exec -it authenticator sh -c "python manage.py cov"
```
