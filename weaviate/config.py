from dataclasses import dataclass
from typing import Union, Optional


@dataclass
class AuthBearerConfig:
    bearer_token: str


@dataclass
class AuthOIDCUserPwConfigConfig:
    user: str
    password: str


@dataclass
class AuthOIDCUserClientFlowConfig:
    client_id: str
    client_secret: str
    scope: Optional[str] = None


AuthConfigs = Union[AuthBearerConfig, AuthOIDCUserPwConfigConfig, AuthOIDCUserClientFlowConfig]


@dataclass
class ClientConfig:
    authentication_config: Optional[AuthConfigs] = None
