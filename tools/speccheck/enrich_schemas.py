#!/usr/bin/env python3
"""One-shot enrichment of request/response schemas for the core OpenAPI groups
(SMS, SMTP, PQC key rotation, SCIM Users/Groups, OIDC/.well-known discovery).

Idempotent: only fills parameters/requestBody/responses/operationId, preserving
the summary and tags already derived by speccheck. Re-run safely after adding
new core endpoints. Bulk doc for non-core groups stays at the derived
summary + generic 200 level.

    python3 tools/speccheck/enrich_schemas.py
"""
import json
import sys
from pathlib import Path

SPEC = Path("internal/handler/spec/openapi.json")

ERR = {"$ref": "#/components/schemas/Error"}


def err_resp(desc):
    return {"description": desc, "content": {"application/json": {"schema": ERR}}}


def json_body(schema, required=True):
    return {"required": required, "content": {"application/json": {"schema": schema}}}


def json_resp(desc, schema):
    return {"description": desc, "content": {"application/json": {"schema": schema}}}


def obj(props, required=None):
    s = {"type": "object", "properties": props}
    if required:
        s["required"] = required
    return s


# ── New reusable component schemas ──────────────────────────────────────────────
NEW_SCHEMAS = {
    "SMSSettings": obj(
        {
            "provider": {"type": "string", "example": "twilio",
                         "description": "Registered SMS connector ID (see GET /connector-catalog?category=sms)."},
            "config": {"type": "object", "additionalProperties": True,
                       "description": "Provider-specific fields. Password-type fields are blanked in responses; "
                                      "leave them empty on update to keep the stored secret."},
            "is_active": {"type": "boolean"},
        },
        ["provider", "config"],
    ),
    "SMTPSettings": obj(
        {
            "host": {"type": "string", "format": "hostname"},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "username": {"type": "string", "nullable": True},
            "password": {"type": "string", "format": "password", "writeOnly": True,
                         "description": "Write-only; never returned. Leave empty on update to keep the stored value."},
            "from_address": {"type": "string", "format": "email"},
            "from_name": {"type": "string"},
            "use_tls": {"type": "boolean"},
            "is_active": {"type": "boolean"},
        },
        ["host", "port", "from_address", "from_name"],
    ),
    "SCIMUser": obj(
        {
            "schemas": {"type": "array", "items": {"type": "string"},
                        "example": ["urn:ietf:params:scim:schemas:core:2.0:User"]},
            "id": {"type": "string", "readOnly": True},
            "userName": {"type": "string"},
            "active": {"type": "boolean"},
            "name": obj({"givenName": {"type": "string"}, "familyName": {"type": "string"}}),
            "emails": {"type": "array", "items": obj({
                "value": {"type": "string", "format": "email"},
                "primary": {"type": "boolean"},
                "type": {"type": "string"},
            })},
        },
        ["userName"],
    ),
    "SCIMGroup": obj(
        {
            "schemas": {"type": "array", "items": {"type": "string"},
                        "example": ["urn:ietf:params:scim:schemas:core:2.0:Group"]},
            "id": {"type": "string", "readOnly": True},
            "displayName": {"type": "string"},
            "members": {"type": "array", "items": obj({"value": {"type": "string"}})},
        },
        ["displayName"],
    ),
    "SCIMPatchOp": obj(
        {
            "schemas": {"type": "array", "items": {"type": "string"},
                        "example": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]},
            "Operations": {"type": "array", "items": obj({
                "op": {"type": "string", "enum": ["add", "remove", "replace"]},
                "path": {"type": "string"},
                "value": {},
            }, ["op"])},
        },
        ["Operations"],
    ),
    "SCIMListResponse": obj({
        "schemas": {"type": "array", "items": {"type": "string"},
                    "example": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]},
        "totalResults": {"type": "integer"},
        "startIndex": {"type": "integer"},
        "itemsPerPage": {"type": "integer"},
        "Resources": {"type": "array", "items": {"type": "object"}},
    }),
    "JWKS": obj({
        "keys": {"type": "array", "items": {"type": "object", "additionalProperties": True},
                 "description": "Array of JWK objects (RFC 7517). Includes the ML-DSA-65 PQC key when pqc_enabled."},
    }),
}

SCIM_JSON = "application/scim+json"


def scim_body(ref):
    return {"required": True, "content": {SCIM_JSON: {"schema": {"$ref": ref}}}}


def scim_resp(desc, ref):
    return {"description": desc, "content": {SCIM_JSON: {"schema": {"$ref": ref}}}}


ID_PARAM = {"in": "path", "name": "id", "required": True, "schema": {"type": "string"}}

# query params for SCIM list
SCIM_LIST_PARAMS = [
    {"in": "query", "name": "filter", "schema": {"type": "string"},
     "description": "SCIM filter, e.g. userName eq \"jane@example.com\"."},
    {"in": "query", "name": "startIndex", "schema": {"type": "integer", "minimum": 1}},
    {"in": "query", "name": "count", "schema": {"type": "integer", "minimum": 0}},
]

# ── Per-operation patches: (path, method) → fields to merge (summary/tags kept) ──
PATCHES = {
    # ── SMS gateway config (org admin) ──
    ("/sms", "get"): {
        "operationId": "getSMSSettings",
        "description": "Returns the org SMS gateway config with secret fields redacted. Empty object if not configured.",
        "responses": {"200": json_resp("Current SMS settings (secrets redacted)",
                                        {"$ref": "#/components/schemas/SMSSettings"})},
    },
    ("/sms", "put"): {
        "operationId": "updateSMSSettings",
        "description": "Create or update the SMS provider config. Blank password fields keep the stored secret; "
                       "the config is validated by instantiating the provider before saving.",
        "requestBody": json_body({"$ref": "#/components/schemas/SMSSettings"}),
        "responses": {
            "200": json_resp("Saved settings (secrets redacted)", {"$ref": "#/components/schemas/SMSSettings"}),
            "400": err_resp("Unknown provider or invalid configuration"),
        },
    },
    ("/sms/test", "post"): {
        "operationId": "testSMSSettings",
        "description": "Send a test SMS to the given number using the stored configuration.",
        "requestBody": json_body(obj({"to": {"type": "string", "description": "E.164 phone number"}}, ["to"])),
        "responses": {
            "200": json_resp("Test SMS sent", obj({"message": {"type": "string"}})),
            "400": err_resp("SMS not configured or invalid configuration"),
            "502": err_resp("SMS gateway delivery failed"),
        },
    },
    # ── SMTP config (org admin) ──
    ("/smtp", "get"): {
        "operationId": "getSMTPSettings",
        "description": "Returns the org SMTP config (password never returned). Empty object if not configured.",
        "responses": {"200": json_resp("Current SMTP settings", {"$ref": "#/components/schemas/SMTPSettings"})},
    },
    ("/smtp", "put"): {
        "operationId": "updateSMTPSettings",
        "requestBody": json_body({"$ref": "#/components/schemas/SMTPSettings"}),
        "responses": {"200": json_resp("Saved settings", {"$ref": "#/components/schemas/SMTPSettings"})},
    },
    ("/smtp/test", "post"): {
        "operationId": "testSMTPSettings",
        "requestBody": json_body(obj({"to": {"type": "string", "format": "email"}}, ["to"])),
        "responses": {
            "200": json_resp("Test email sent", obj({"message": {"type": "string"}})),
            "400": err_resp("SMTP not configured"),
            "502": err_resp("SMTP delivery failed"),
        },
    },
    # ── Signing-key rotation (superadmin) ──
    ("/rotate-signing-key", "post"): {
        "operationId": "rotateSigningKey",
        "description": "Generate a new classical RSA signing key and retire the current one. "
                       "The retired key stays in the JWKS for a grace period.",
        "responses": {
            "200": json_resp("New active key id", obj({"kid": {"type": "string"}})),
            "500": err_resp("Rotation failed"),
        },
    },
    ("/rotate-pqc-signing-key", "post"): {
        "operationId": "rotatePQCSigningKey",
        "description": "Generate a new ML-DSA-65 PQC signing key and retire the current one. "
                       "Returns 404 when pqc_enabled is false.",
        "responses": {
            "200": json_resp("New active PQC key id", obj({"kid": {"type": "string"}})),
            "404": err_resp("PQC signing is not enabled"),
            "500": err_resp("Rotation failed"),
        },
    },
    # ── SCIM 2.0 Users (RFC 7644) ──
    ("/Users", "get"): {
        "operationId": "scimListUsers",
        "parameters": SCIM_LIST_PARAMS,
        "responses": {"200": scim_resp("SCIM ListResponse of users", "#/components/schemas/SCIMListResponse")},
    },
    ("/Users", "post"): {
        "operationId": "scimCreateUser",
        "requestBody": scim_body("#/components/schemas/SCIMUser"),
        "responses": {"201": scim_resp("Created", "#/components/schemas/SCIMUser"),
                      "409": err_resp("User already exists")},
    },
    ("/Users/{id}", "get"): {
        "operationId": "scimGetUser", "parameters": [ID_PARAM],
        "responses": {"200": scim_resp("User", "#/components/schemas/SCIMUser"),
                      "404": err_resp("User not found")},
    },
    ("/Users/{id}", "put"): {
        "operationId": "scimReplaceUser", "parameters": [ID_PARAM],
        "requestBody": scim_body("#/components/schemas/SCIMUser"),
        "responses": {"200": scim_resp("Replaced user", "#/components/schemas/SCIMUser"),
                      "404": err_resp("User not found")},
    },
    ("/Users/{id}", "patch"): {
        "operationId": "scimPatchUser", "parameters": [ID_PARAM],
        "requestBody": scim_body("#/components/schemas/SCIMPatchOp"),
        "responses": {"200": scim_resp("Patched user", "#/components/schemas/SCIMUser"),
                      "404": err_resp("User not found")},
    },
    ("/Users/{id}", "delete"): {
        "operationId": "scimDeleteUser", "parameters": [ID_PARAM],
        "responses": {"204": {"description": "Deleted"}, "404": err_resp("User not found")},
    },
    # ── SCIM 2.0 Groups ──
    ("/Groups", "get"): {
        "operationId": "scimListGroups", "parameters": SCIM_LIST_PARAMS,
        "responses": {"200": scim_resp("SCIM ListResponse of groups", "#/components/schemas/SCIMListResponse")},
    },
    ("/Groups", "post"): {
        "operationId": "scimCreateGroup",
        "requestBody": scim_body("#/components/schemas/SCIMGroup"),
        "responses": {"201": scim_resp("Created", "#/components/schemas/SCIMGroup")},
    },
    ("/Groups/{id}", "get"): {
        "operationId": "scimGetGroup", "parameters": [ID_PARAM],
        "responses": {"200": scim_resp("Group", "#/components/schemas/SCIMGroup"),
                      "404": err_resp("Group not found")},
    },
    ("/Groups/{id}", "put"): {
        "operationId": "scimReplaceGroup", "parameters": [ID_PARAM],
        "requestBody": scim_body("#/components/schemas/SCIMGroup"),
        "responses": {"200": scim_resp("Replaced group", "#/components/schemas/SCIMGroup"),
                      "404": err_resp("Group not found")},
    },
    ("/Groups/{id}", "patch"): {
        "operationId": "scimPatchGroup", "parameters": [ID_PARAM],
        "requestBody": scim_body("#/components/schemas/SCIMPatchOp"),
        "responses": {"200": scim_resp("Patched group", "#/components/schemas/SCIMGroup"),
                      "404": err_resp("Group not found")},
    },
    ("/Groups/{id}", "delete"): {
        "operationId": "scimDeleteGroup", "parameters": [ID_PARAM],
        "responses": {"204": {"description": "Deleted"}, "404": err_resp("Group not found")},
    },
}

# ── Public OIDC / .well-known discovery (no auth) ───────────────────────────────
DISCOVERY = {
    "/.well-known/openid-configuration": ("oidcDiscovery", "OpenID Provider metadata", "#/components/schemas/OIDCDiscovery"),
    "/{org_slug}/.well-known/openid-configuration": ("oidcDiscoveryOrg", "OpenID Provider metadata", "#/components/schemas/OIDCDiscovery"),
    "/.well-known/oauth-authorization-server": ("oauthASMetadata", "OAuth 2.0 Authorization Server metadata (RFC 8414)", "#/components/schemas/OIDCDiscovery"),
    "/.well-known/oauth-authorization-server/{org_slug}": ("oauthASMetadataOrg", "OAuth 2.0 Authorization Server metadata (RFC 8414)", "#/components/schemas/OIDCDiscovery"),
    "/.well-known/jwks.json": ("jwks", "JSON Web Key Set", "#/components/schemas/JWKS"),
    "/{org_slug}/.well-known/jwks.json": ("jwksOrg", "JSON Web Key Set", "#/components/schemas/JWKS"),
}

# discovery endpoints returning a free-form metadata object
DISCOVERY_OBJ = {
    "/.well-known/openid-credential-issuer": ("oid4vciIssuerMetadata", "OID4VCI credential issuer metadata"),
    "/.well-known/openid-credential-issuer/{org_slug}": ("oid4vciIssuerMetadataOrg", "OID4VCI credential issuer metadata"),
    "/.well-known/ssf-configuration": ("ssfMetadata", "Shared Signals Framework transmitter metadata"),
}


def main():
    spec = json.loads(SPEC.read_text())
    paths = spec["paths"]
    schemas = spec.setdefault("components", {}).setdefault("schemas", {})
    for name, sch in NEW_SCHEMAS.items():
        schemas[name] = sch

    # org_slug param may not exist as a component; ensure presence (it does in this spec).
    params = spec["components"].setdefault("parameters", {})
    params.setdefault("OrgSlug", {"in": "path", "name": "org_slug", "required": True, "schema": {"type": "string"}})

    patched = 0

    def apply(path, method, fields, public=False):
        nonlocal patched
        if path not in paths or method not in paths[path]:
            print(f"  skip (absent): {method.upper()} {path}", file=sys.stderr)
            return
        op = paths[path][method]
        for k, v in fields.items():
            op[k] = v
        if public:
            op["security"] = []
        # Path parameters ({org_slug}, {id}, …) are injected by speccheck -enrich,
        # which resolves $ref params and de-duplicates — run it after this script.
        patched += 1

    for (path, method), fields in PATCHES.items():
        apply(path, method, fields)

    for path, (opid, desc, ref) in DISCOVERY.items():
        apply(path, "get", {
            "operationId": opid, "description": desc,
            "responses": {"200": json_resp(desc, {"$ref": ref})},
        }, public=True)

    for path, (opid, desc) in DISCOVERY_OBJ.items():
        apply(path, "get", {
            "operationId": opid, "description": desc,
            "responses": {"200": json_resp(desc, {"type": "object", "additionalProperties": True})},
        }, public=True)

    # openid-federation returns a signed JWT (entity statement), not JSON
    if "/.well-known/openid-federation" in paths:
        op = paths["/.well-known/openid-federation"]["get"]
        op["operationId"] = "openidFederationEntityConfig"
        op["description"] = "OpenID Federation 1.0 entity configuration (signed JWT)."
        op["security"] = []
        op["responses"] = {"200": {"description": "Entity statement",
                                   "content": {"application/entity-statement+jwt": {"schema": {"type": "string"}}}}}
        patched += 1

    SPEC.write_text(json.dumps(spec, indent=2) + "\n")
    print(f"enrich_schemas: patched {patched} operation(s); added {len(NEW_SCHEMAS)} component schema(s).")


if __name__ == "__main__":
    main()
