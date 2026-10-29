ASPNET_TO_STANDARD = {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "sub",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "role",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": "given_name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": "family_name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone": "phone_number",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender": "gender",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode": "postal_code",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid": "sid",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/webpage": "website",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country": "country",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/stateorprovince": "region",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/userdata": "userdata",
    "http://schemas.microsoft.com/claims/identityprovider": "idp",
}

STANDARD_TO_ASPNET = {v: k for k, v in ASPNET_TO_STANDARD.items()}


def is_aspnet_token(payload):
    if not isinstance(payload, dict):
        return False
    return any(key.startswith("http://schemas.") for key in payload.keys())


def normalize_aspnet_claims(payload):
    if not isinstance(payload, dict):
        return payload
    normalized = {}
    for key, value in payload.items():
        clean_key = ASPNET_TO_STANDARD.get(key, key)
        normalized[clean_key] = value
    return normalized


def to_aspnet_claims(claims):
    if not isinstance(claims, dict):
        return claims
    aspnet_claims = {}
    for key, value in claims.items():
        mapped_key = STANDARD_TO_ASPNET.get(key, key)
        aspnet_claims[mapped_key] = value
    return aspnet_claims


def check_aspnet_issues(payload):
    findings = []
    if not isinstance(payload, dict):
        return findings

    has_std_role = "role" in payload or "roles" in payload
    ms_role_key = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    has_ms_role = ms_role_key in payload

    if has_std_role and not has_ms_role:
        findings.append({
            "severity": "HIGH",
            "title": "ASP.NET Core Role Incompatibility",
            "description": (
                "Token uses standard 'role' claim instead of Microsoft schema URI. "
                "ASP.NET Core User.IsInRole() will fail to recognize the role unless "
                "ClaimTypeMap is disabled via ClearPrefix() or InboundClaimTypeMap."
            ),
        })

    if has_std_role and has_ms_role:
        findings.append({
            "severity": "MEDIUM",
            "title": "ASP.NET Core Role Claim Confusion",
            "description": (
                "Token contains both standard 'role' and Microsoft schema role URI. "
                "Inconsistent claim validation in backend middleware can lead to privilege desync."
            ),
        })

    has_std_name = "name" in payload or "sub" in payload
    ms_name_key = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    ms_sub_key = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"

    if has_std_name and not (ms_name_key in payload or ms_sub_key in payload) and is_aspnet_token(payload):
        findings.append({
            "severity": "LOW",
            "title": "Mixed Identity Schema",
            "description": (
                "Token mixes ASP.NET XML schemas with standard subject/name claims."
            ),
        })

    return findings
