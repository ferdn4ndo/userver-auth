#!/bin/bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
source ./colors.sh

case "${ENV_MODE:-development}" in
  prod)
    echo -e "${COLOR_BLUE}Starting in production mode...${COLOR_RESET}"
    export APP_SETTINGS="project.server.config.ProductionConfig"
    ;;
  *)
    echo -e "${COLOR_BLUE}Starting in development mode...${COLOR_RESET}"
    export APP_SETTINGS="project.server.config.DevelopmentConfig"
    ;;
esac

# setup.sh uses bash features (e.g. ${var//pat/rep}); must not run under plain sh.
if [ "${SKIP_DB_SETUP:-0}" = "1" ]; then
  echo -e "${COLOR_YELLOW}SKIP_DB_SETUP=1: skipping database setup (migrations not applied).${COLOR_RESET}"
else
  bash ./setup.sh
fi

PORT="${FLASK_PORT:-5000}"
THREADS="${WAITRESS_THREADS:-8}"
[ -n "$THREADS" ] || THREADS=8

# Avoid Flask CLI for the web process: faster startup and Waitress sets its logger to INFO
# so "Serving on ..." appears in docker logs (Flask often leaves root logging at WARNING).
echo -e "${COLOR_BLUE}Starting Waitress on 0.0.0.0:${PORT} (${THREADS} threads)...${COLOR_RESET}"
exec python -m waitress \
  --listen="0.0.0.0:${PORT}" \
  --threads="${THREADS}" \
  project.server:app
