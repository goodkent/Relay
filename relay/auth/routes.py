from __future__ import annotations
from datetime import datetime
from urllib.parse import urlsplit, urlencode

from flask import redirect, render_template, request, url_for, Response, flash, current_app
from flask_login import current_user, login_user, logout_user, login_required

from relay.auth import bp
from relay.extensions import db
from relay.models.user import User

from authlib.jose.errors import JoseError
from relay.auth.provider import clear_provider_cache, get_oauth_client, get_provider_for_domain, get_saml_provider_for_domain
from relay.models.organization import OIDCProvider, Organization


from flask import session, abort

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

from relay.auth.saml import _build_saml_settings, extract_identity, prepare_flask_request
from relay.models.organization import SAMLProvider
from relay.extensions import csrf

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
        oidc_provider = get_provider_for_domain(domain)
        saml_provider = get_saml_provider_for_domain(domain)

        if oidc_provider is not None:
            if oidc_provider.organization.sso_required:
                return _initiate_oidc(oidc_provider)
            return render_template(
                "auth/login.html",
                email=email,
                show_password=True,
                sso_url=url_for("auth.sso_redirect", slug=oidc_provider.organization.slug)
            )


        if saml_provider is not None:
            slug = saml_provider.organization.slug
            if saml_provider.enforce_sso:
                return redirect(url_for("auth.saml_login", slug =slug))
            return render_template(
                "auth/login.html",
                email=email,
                show_password=True,
                sso_url= url_for("auth.saml_login", slug=slug)
            )
        
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

    if "saml_name_id" in session:
        org_id = session.get("saml_org_id")
        provider = db.session.scalar(
            db.select(SAMLProvider).where(SAMLProvider.organization_id == org_id)
        )            
        if provider:
            settings = _build_saml_settings(provider)
            auth = OneLogin_Saml2_Auth(prepare_flask_request(), old_settings=settings)
            slo_url = auth.logout(
                name_id = session.get("saml_name_id"),
                session_index=session.get("saml_session_index"),
                nq = None,
                name_id_format=session.get("saml_name_id_format")
            )
            return redirect(slo_url)
    
    
    session.clear()
        
    return redirect(url_for("auth.login"))

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

@bp.route("saml/metadata")
def saml_metadata():
    placeholder = SAMLProvider(
        idp_entity_id="",
        idp_sso_url="",
        idp_x509_cert=""
    )

    settings_dict = _build_saml_settings(placeholder)
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    saml_settings = OneLogin_Saml2_Settings(settings=settings_dict, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()

    return Response(metadata, mimetype="application/xml")

@bp.route("/saml/<slug>/login")
def saml_login(slug:str):
    provider = db.session.scalar(
        db.select(SAMLProvider)
        .join(SAMLProvider.organization)
        .where(db.text("organizations.slug = :slug"))
        .params(slug=slug)
    )

    if provider is None:
        abort(404)
    
    session["pending_saml_org_id"] = provider.organization_id

    next_url = request.args.get("next","")
    if next_url and urlsplit(next_url).netloc:
        next_url = ""
    session["next_url"] = next_url
    settings = _build_saml_settings(provider)
    
    settings["idp"]["_relay_config"] = provider
    auth = OneLogin_Saml2_Auth(prepare_flask_request(), old_settings=settings)
    return redirect(auth.login(return_to=provider.organization_id))

@bp.route("/saml/acs", methods=["POST"])
@csrf.exempt
def saml_acs():
    org_id = request.form.get("RelayState")
    if not org_id:
        
        return redirect(url_for("auth.login"))
    
    provider = db.session.scalar(
        db.select(SAMLProvider)
        .where(SAMLProvider.organization_id == org_id)
    )

    if provider is None:
        abort(400)
    
    settings = _build_saml_settings(provider)
    settings["idp"]["_relay_config"] = provider
    auth = OneLogin_Saml2_Auth(prepare_flask_request(), old_settings=settings)
    auth.process_response()
    
    errors=auth.get_errors()

    if errors or not auth.is_authenticated():
        return redirect(url_for("auth.login", error="saml_failed"))
    
    try:
        email, display_name = extract_identity(auth)
    except ValueError:
        
        return redirect(url_for("auth.login", error="saml_no_email"))
    
    from relay.auth.jit import provision_user_saml
    user = provision_user_saml(
        email=email,
        display_name=display_name,
        organization=provider.organization,
    )

    if not user.active:
        return redirect(url_for("auth.login", error="account_disabled"))
    
    login_user(user, remember=False)
    session["saml_name_id"] = auth.get_nameid()
    session["saml_name_id_format"] = auth.get_nameid_format()
    session["saml_session_index"] = auth.get_session_index()
    session["saml_org_id"] = provider.organization_id

    next_url = session.pop("next_url", None) or url_for("main.index")
    return redirect(next_url)

@bp.route("/saml/setup/<slug>", methods=["GET","POST"])
@login_required
def saml_setup(slug: str):
    
    
    organization = db.session.scalar(db.select(Organization).where(Organization.slug ==slug))

    if organization is None:
        abort(404)
    
    if current_user.organization_id != organization.id:
        abort(403)

    if request.method=="POST":
        idp_entity_id = request.form.get("idp_entity_id", "").strip()
        idp_sso_url = request.form.get("idp_sso_url","").strip()
        idp_x509_cert = request.form.get("idp_x509_cert","").strip()

        if not all([idp_entity_id, idp_sso_url, idp_x509_cert]):
            return render_template(
                "auth/saml_setup.html",
                organization=organization,
                error="All fields are required"
            )

        provider = organization.saml_provider or SAMLProvider(
            organization_id=organization.id)
        
        provider.idp_entity_id = idp_entity_id
        provider.idp_sso_url = idp_sso_url
        provider.idp_x509_cert = idp_x509_cert
        db.session.add(provider)
        db.session.commit()
        return redirect(url_for("auth.saml_setup", slug=slug, saved=1))

    return render_template("auth/saml_setup.html", organization=organization)

@bp.route("/saml/setup/<slug>/import_metadata", methods=["POST"])
@login_required
def saml_import_metadata(slug:str):
    org = db.session.scalar(db.select(Organization).where(Organization.slug == slug))

    if org is None or org.saml_provider is None:
        abort(404)

    metadata_xml = request.form.get("metadata_xml", "").strip()
    if not metadata_xml:
        flash("Paste the IdP metadata XL to import.", "warning")
        return redirect(url_for("auth.saml_setup", slug=slug))

    try:
        parsed = OneLogin_Saml2_IdPMetadataParser.parse(metadata_xml.encode())
        idp = parsed.get("idp",{})
        org.saml_provider.idp_entity_id = idp.get("entityId","")
        org.saml_provider.idp_sso_url = idp.get("singleSignOnService", {}).get("url","")
        certs = idp.get("x509certMulti",{}).get("signing",[]) or [idp.get("x509cert","")]
        org.saml_provider.idp_x509_cert = certs[0] if certs else ""
        db.session.commit()
        flash("IdP metadata imported successfull.","success")
    except Exception as exc:
        flash(f"Could not parse metadata: {exc}","danger")
    
    return redirect(url_for("auth.saml_setup",slug=slug)
                    )

@bp.route("/saml/sls")
def saml_sls():

    org_id = session.get("saml_org_id")
    if org_id:
        provider = db.session.scalar(
              db.select(SAMLProvider).where(SAMLProvider.organization_id == org_id)
          )
        if provider:
            settings = _build_saml_settings(provider)
            auth = OneLogin_Saml2_Auth(prepare_flask_request(), old_settings=settings)
            auth.process_slo(keep_local_session=True)
            if auth.get_errors():
                current_app.logger.error("SAML SLO errors: %s", auth.get_last_error_reason())
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))