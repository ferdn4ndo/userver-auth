from flask import Blueprint, render_template

docs_blueprint = Blueprint('docs', __name__, template_folder='templates', static_folder='static', static_url_path='/docs-static')


@docs_blueprint.route('/')
def index():
    return render_template('index.html')
