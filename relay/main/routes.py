from flask import render_template
from relay.main import bp

@bp.route("/")
def index():
    return render_template("main/index.html")