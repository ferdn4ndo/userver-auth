#!/bin/bash


if [ "${ENV_MODE}" == "prod" ]
then
  echo "Starting in production mode..."
  export APP_SETTINGS="project.server.config.ProductionConfig"

  python manage.py run_prod
else
  echo "Starting in development mode..."
  export APP_SETTINGS="project.server.config.DevelopmentConfig"

  python manage.py runserver -h 0.0.0.0 -p ${FLASK_PORT}
  # yarn serve
fi
