from __future__ import annotations
from datetime import datetime
from urllib.parse import urlsplit

from flask import redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user

from relay.auth import bp
from relay.extensions import db
from relay.models.user import User

@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    
    error: str | None = None

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = db.session.scalar(db.select(User).where(User.email == email))
        
        if user is None or not user.check_password(password):
            error = "Invalid email or password."
        elif not user.active:
            error = "This account has been disabled."
        else:
            login_user(user, remember=False)
            user.last_login_at = datetime.utcnow()
            db.session.commit()

            next_url = request.args.get("next","")

            if next_url and urlsplit(next_url).netloc:
                next_url = ""
            return redirect(next_url or url_for("main.index"))

    return render_template("auth/login.html", error=error)

@bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("main.index"))