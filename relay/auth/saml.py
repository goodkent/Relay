from __future__ import annotations
from urllib.parse import urlparse
from flask import request, url_for
from relay.models.organization import SAMLProvider

def _strip_pem(pem: str) -> str:
    """Remove PEM headers and newlines — python3-saml expects raw base64."""
    return (
        pem
        .replace("-----BEGIN CERTIFICATE-----","")
        .replace("-----END CERTIFICATE-----","")
        .replace("-----BEGIN RSA PRIVATE KEY-----","")
        .replace("-----END RSA PRIVATE KEY-----","")
        .replace("\n","")
        .strip()
    )

def _build_saml_settings(config: SAMLProvider) -> dict:
    return {
        "strict": True,
        "security": {"allowRepeatAttributeName": True},
        "sp": {
            "entityId": url_for("auth.saml_metadata", _external=True),
            "assertionConsumerService": {
                "url": url_for("auth.saml_acs", _external=True),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": config.name_id_format,
            "x509cert": _strip_pem(config.sp_certificate or ""),
            "privateKey": _strip_pem(config.sp_private_key or ""),
            "singleLogoutService": {
                "url": url_for("auth.saml_sls", _external=True)}
            },
        "idp": {
            "entityId": config.idp_entity_id,
            "singleSignOnService": {
                "url": config.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": config.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
        "x509cert": config.idp_x509_cert,
        },
    }

def prepare_flask_request() -> dict:
    url_data = urlparse(request.url)
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "server_port": url_data.port,
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
    }

def extract_identity(auth) -> tuple[str, str | None]:
    config: SAMLProvider = auth._settings.get_idp_data()["_relay_config"]
    attributes = auth.get_attributes()
    email: str | None = None
    if config.email_attribute and config.email_attribute in attributes:
        values = attributes[config.email_attribute]
        email = values[0].lower() if values else None
    if not email:
        email = (auth.get_nameid() or "").lower()
    
    if not email:
        raise ValueError("SAML response contained no usable email address")
    
    display_name: str | None = None
    if config.name_attribute and config.name_attribute in attributes:
        values = attributes[config.name_attribute]
        display_name = values[0] if values else None
    
    return email, display_name