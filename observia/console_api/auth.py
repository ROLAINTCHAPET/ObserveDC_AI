"""Authentification forte et RBAC de la console (NFR-04).

Jeton JWT émis par le SSO (OIDC, RS256 via JWKS) ou, pour le pilote, HS256 partagé.
Sans configuration, tout accès est refusé (échec sûr). Rôles dérivés du RACI (SPSD §4.4) :
  viewer      : consultation
  oncall      : + kill switch, traitement des escalades (astreinte)
  admin       : + validation niveau 3, kill switch (administrateur DC)
  ops_manager : + ouverture des niveaux d'autonomie (responsable d'exploitation)
  auditor     : consultation du journal d'audit
"""
from dataclasses import dataclass
from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException, Request

from shared.config import get_settings

ROLES = {"viewer", "oncall", "admin", "ops_manager", "auditor"}


@dataclass
class User:
    name: str
    roles: set[str]


@lru_cache
def _jwks_client(url: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(url)


def decode_token(token: str) -> dict:
    settings = get_settings()
    options = {"require": ["exp", "sub"]}
    if settings.oidc_jwks_url:
        key = _jwks_client(settings.oidc_jwks_url).get_signing_key_from_jwt(token).key
        return jwt.decode(token, key, algorithms=["RS256", "ES256"], audience=settings.oidc_audience,
                          options={**options, "verify_aud": bool(settings.oidc_audience)})
    if settings.console_jwt_secret:
        return jwt.decode(token, settings.console_jwt_secret, algorithms=["HS256"],
                          audience=settings.oidc_audience, options={**options, "verify_aud": bool(settings.oidc_audience)})
    raise HTTPException(status_code=503, detail="authentification non configurée")


def current_user(request: Request) -> User:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="jeton requis")
    try:
        claims = decode_token(header[7:])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"jeton invalide : {exc}") from exc
    roles = set(claims.get("roles") or (claims.get("realm_access") or {}).get("roles") or []) & ROLES
    return User(name=claims.get("preferred_username") or claims["sub"], roles=roles)


def require(*roles: str):
    def dep(user: User = Depends(current_user)) -> User:
        if not user.roles & set(roles):
            raise HTTPException(status_code=403, detail=f"rôle requis : {' ou '.join(roles)}")
        return user

    return dep


ANY_READER = ("viewer", "oncall", "admin", "ops_manager")
