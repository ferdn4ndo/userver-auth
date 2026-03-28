# manage.py

import os
import sys
import unittest

import coverage
from flask.cli import with_appcontext
from flask_migrate import Migrate
from waitress import serve

from project.server import app, db, models

migrate = Migrate(app, db)

COV = coverage.coverage(
    branch=True,
    include='project/*',
    omit=[
        'project/tests/*',
        'project/server/config.py',
        'project/server/*/__init__.py'
    ]
)


@app.cli.command()
def test():
    """Runs the unit tests without test coverage."""
    tests = unittest.TestLoader().discover('project/tests', pattern='test*.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    sys.exit(0 if result.wasSuccessful() else 1)


@app.cli.command()
def cov():
    """Runs the unit tests with coverage."""
    COV.start()
    tests = unittest.TestLoader().discover('project/tests')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        COV.stop()
        COV.save()
        print('Coverage Summary:')
        COV.report()
        basedir = os.path.abspath(os.path.dirname(__file__))
        covdir = os.path.join(basedir, 'tmp/coverage')
        COV.html_report(directory=covdir)
        print('HTML version: file://%s/index.html' % covdir)
        COV.erase()
        sys.exit(0)
    sys.exit(1)


@app.cli.command('create-db')
@with_appcontext
def create_db():
    """Creates the db tables."""
    db.create_all()


@app.cli.command('drop-db')
@with_appcontext
def drop_db():
    """Drops the db tables."""
    db.drop_all()


@app.cli.command('run-prod')
def run_prod():
    """Run the app under Waitress (local use; Docker uses entrypoint.sh + python -m waitress)."""
    port = int(os.environ.get('FLASK_PORT', '5000'))
    raw_threads = os.environ.get('WAITRESS_THREADS', '8') or '8'
    threads = int(raw_threads)
    print(f'Waitress on 0.0.0.0:{port} ({threads} threads)', flush=True)
    serve(app, host='0.0.0.0', port=port, threads=threads)
