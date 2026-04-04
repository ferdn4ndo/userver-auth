FROM python:3.14-alpine

ARG BUILD_DATE=unknown
ARG BUILD_VERSION=unknown
ARG VCS_REF=unknown

LABEL maintainer="Fernando Constantino <const.fernando@gmail.com>"
LABEL org.opencontainers.image.title="userver-auth"
LABEL org.opencontainers.image.description="JWT authentication microservice (Flask / PostgreSQL)"
LABEL org.opencontainers.image.url="https://github.com/ferdn4ndo/userver-auth"
LABEL org.opencontainers.image.source="https://github.com/ferdn4ndo/userver-auth"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${VCS_REF}"

# Setting PYTHONUNBUFFERED to a non empty value ensures that the python output is sent straight to terminal (e.g. your
# container log) without being first buffered and that you can see the output of your application (e.g. django logs) in
# real time. This also ensures that no partial output is held in a buffer somewhere and never written in case the python
# application crashes.
# Font: https://stackoverflow.com/questions/59812009/what-is-the-use-of-pythonunbuffered-in-docker-file
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
ENV FLASK_APP=manage:app

WORKDIR /code/

COPY requirements.txt /code/requirements.txt

ENV LIBRARY_PATH=/lib:/usr/lib

# Install packages before requirements (both run and build ones)
RUN set -ex \
    && apk add --no-cache --virtual .build-deps \
       make \
       gcc \
       musl-dev \
       zlib-dev \
       py-pip \
       postgresql-dev \
       libffi-dev \
       openssl-dev \
    && apk add --no-cache \
       bash \
       gettext \
       build-base \
       postgresql-libs \
       postgresql-client \
    && python -m pip install -U --force-reinstall pip \
    && pip install --no-cache-dir -r /code/requirements.txt \
    && apk --purge del .build-deps \
    && rm -rf /tmp/requirements.txt

# Application source (after deps layer for better cache)
COPY . /code/

EXPOSE 5000

# Uses FLASK_PORT when set (matches entrypoint / Waitress); default 5000.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import os,urllib.request as u; p=os.environ.get('FLASK_PORT','5000'); u.urlopen(f'http://127.0.0.1:{p}/healthz', timeout=4)"

CMD ["/bin/bash", "entrypoint.sh"]
