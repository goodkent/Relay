from __future__ import annotations
from datetime import datetime
from urllib.parse import urlsplit, urlencode

from flask import redirect, render_template, request, url_for, Response
from flask_login import current_user, login_user, logout_user

from relay.auth import bp
from relay.extensions import db
from relay.models.user import User

from authlib.jose.errors import JoseError
from relay.auth.provider import clear_provider_cache, get_oauth_client, get_provider_for_domain
from relay.models.organization import OIDCProvider

from flask import session, abort

@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    
    error: str | None = None
    sso_url: str | None = None

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        domain = email.rsplit("@", 1)[-1] if "@" in email else ""
        provider = get_provider_for_domain(domain) if domain else None

        print(f"DEBUG domain={domain!r}  provider={provider}") 
        if provider is not None and provider.organization.sso_required:
            return _initiate_oidc(provider)
        
        if provider is not None:
            sso_url = url_for("auth.sso_redirect", slug=provider.organization.slug)
        
        if not sso_url or password:
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

    return render_template("auth/login.html", error=error, sso_url=sso_url)

@bp.route("/logout")
def logout():
    org_id: str | None = None
    if current_user.is_authenticated:
        org_id = current_user.organization_id

    id_token: str | None = session.pop("id_token", None)
    logout_user()

    if org_id:
        provider = db.session.scalar(
            db.select(OIDCProvider).where(OIDCProvider.organization_id == org_id)
        )

        if provider:
            client = get_oauth_client(provider)
            try:
                metadata = client.load_server_metadata()
                end_session_endpoint = metadata.get("end_session_endpoint")
            except Exception:
                end_session_endpoint = None
            
            if end_session_endpoint:
                params: dict[str, str] = {
                    "post_logout_redirect_uri" : url_for("auth.login", _external=True)
                }
                if id_token:
                    params["id_token_hint"] = id_token
                return redirect(
                    f"{end_session_endpoint}?{urlencode(params)}"
                )
            
    return redirect(url_for("main.index"))

@bp.route("/sso/<slug>")
def sso_redirect(slug: str):
    provider = db.session.scalar(db.select(OIDCProvider).join(OIDCProvider.organization).where(db.text("organizations.slug = :slug")).params(slug=slug))
    if provider is None:
        abort(404)
    return _initiate_oidc(provider)

def _initiate_oidc(provider: OIDCProvider):
    session["pending_org_id"] = provider.organization_id
    next_url = request.args.get("next","")
    if next_url and urlsplit(next_url).netloc:
        next_url = ""
    session["next_url"] = next_url
    client = get_oauth_client(provider)
    return client.authorize_redirect(redirect_uri=url_for("auth.callback", _external=True),)

@bp.route("/callback")
def callback() -> Response:
    print(request.url)
    org_id = session.pop("pending_org_id", None)
    if not org_id:
        return redirect(url_for("auth.login"))
    
    provider = db.session.scalar(db.select(OIDCProvider).where(OIDCProvider.organization_id == org_id))

    if provider is None:
        abort(404)
    
    client = get_oauth_client(provider)
    try:
        token = client.authorize_access_token()
    except JoseError:
        clear_provider_cache(provider.organization_id)
        client = get_oauth_client(provider)
        try:
            token = client.authorize_access_token()
        except Exception:
            return redirect(url_for("auth.login", error="sso_failed"))
        
    if id_token := token.get("id_token"):
        session["id_token"] = id_token

    claims = token.get("userinfo") or {}
    if not claims:
        claims = client.userinfo(token=token)
    
    from relay.auth.jit import provision_user
    user = provision_user(claims, provider.organization)

    if not user.active:
        return redirect(url_for("auth.login", error="account_disabled"))
    
    login_user(user, remember=False)
    next_url = session.pop("next_url", None) or url_for("main.index")
    return redirect(next_url)