from __future__ import annotations
import secrets

import dns.resolver
import dns.exception

from relay.extensions import db
from relay.models.organization import OrgDomain

def generate_verification_token(domain_record: OrgDomain) -> str:
    token = secrets.token_urlsafe(32)
    domain_record.verification_token = token
    db.session.commit()
    return token

def check_domain_verification(domain_record: OrgDomain) -> bool:
    if not domain_record.verification_token:
        return False

    expected = f"relay-verify={domain_record.verfication_token}"
    query_name = f"_relay-verification.{domain_record.domain}"

    try:
        answers = dns.resolver.resolve(query_name, "TXT")
        for rdata in answers:
            txt_value =  b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt_value == expected:
                domain_record.verified = True
                db.session.commit()
                return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass

    return False