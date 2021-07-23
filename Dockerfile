FROM python:3.7-alpine3.13
LABEL maintaner="Fernando Constantino <const.fernando@gmail.com>"

# Setting PYTHONUNBUFFERED to a non empty value ensures that the python output is sent straight to terminal (e.g. your
# container log) without being first buffered and that you can see the output of your application (e.g. django logs) in
# real time. This also ensures that no partial output is held in a buffer somewhere and never written in case the python
# application crashes.
# Font: https://stackoverflow.com/questions/59812009/what-is-the-use-of-pythonunbuffered-in-docker-file
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

WORKDIR /code/

# Copy in your requirements file
ADD requirements.txt /code/requirements.txt

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
       libressl-dev \
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

EXPOSE 5000
CMD ["/bin/sh", "entrypoint.sh"]
