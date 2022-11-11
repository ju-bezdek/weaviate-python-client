"""
Authentication class definitions.
"""
from typing import Optional, Tuple

from authlib.integrations.requests_client import OAuth2Session

from weaviate.config import (
    AuthConfigs,
    AuthBearerConfig,
    AuthOIDCUserClientFlowConfig,
    AuthOIDCUserPwConfigConfig,
)
from weaviate.exceptions import MissingScopeException


class Credentials:
    def __init__(self, config: AuthConfigs, open_id_config_url: str, connection: "Connection"):
        self._credentials_body = {}
        self._config: AuthConfigs = config
        self._open_id_config_url: str = open_id_config_url
        self._connection: "Connection" = connection
        self._token_endpoint: str = self._get_token_endpoint(open_id_config_url)

        self._token: Optional[str] = None

    def _get_token_endpoint(self, open_id_config_url: str) -> str:
        response_auth = self._connection.get(open_id_config_url, external_url=True)
        return response_auth.json()["token_endpoint"]

    def get_auth_token(self) -> Tuple[str, int]:
        if isinstance(self._config, AuthBearerConfig):
            return "", 1
        elif isinstance(self._config, AuthOIDCUserClientFlowConfig):
            return self._get_add_oidc_authentication(self._token_endpoint)
        else:
            assert isinstance(self._config, AuthOIDCUserPwConfigConfig)
            return "", 1

    def _get_add_oidc_authentication(self, token_endpoint: str) -> Tuple[str, int]:
        assert isinstance(self._config, AuthOIDCUserClientFlowConfig)
        if self._config.scope is not None:
            scope = self._config.scope
        else:
            # hardcode a few commonly used scope urls
            if token_endpoint.startswith("https://login.microsoftonline.com"):
                scope = "https://graph.microsoft.com/.default"
            else:
                raise MissingScopeException

        session = OAuth2Session(
            client_id=self._config.client_id,
            client_secret=self._config.client_secret,
            token_endpoint_auth_method="client_secret_post",
            scope=scope,
            token_endpoint=token_endpoint,
            grant_type="client_credentials",
            token={"access_token": None, "expires_in": -100},
        )
        return session.fetch_token()["access_token"], session.fetch_token()["expires_in"]


# class AuthCredentials(ABC):
#     """
#     Base class for getting the grant type and credentials.
#     """
#
#     def __init__(self):
#         self._credentials_body = {}
#
#     @abstractmethod
#     def get_credentials(self) -> dict:
#         """
#         Get credentials.
#         """
#
#
# class AuthClientCredentials(AuthCredentials):
#     """
#     Using a client secret for authentication.
#     In case of grant type client credentials.
#     """
#
#     def __init__(self, client_secret: str):
#         """
#         Using a client secret for authentication.
#         In case of grant type client credentials.
#
#         Parameters
#         ----------
#         client_secret : str
#             The client secret credentials, NOT access token.
#         """
#
#         super().__init__()
#         self._credentials_body["grant_type"] = "client_credentials"
#         self._client_secret_encoded = base64.b64encode(client_secret.encode("utf-8")).decode(
#             "utf-8"
#         )
#
#     def get_credentials(self) -> dict:
#         """
#         Get decoded credentials.
#
#         Returns
#         -------
#         dict
#             Decoded credentials.
#         """
#
#         return_body = copy.deepcopy(self._credentials_body)
#         return_body["client_secret"] = base64.b64decode(
#             self._client_secret_encoded.encode("utf-8")
#         ).decode("utf-8")
#         return return_body


# class AuthClientOIDCCredentials(AuthCredentials):
#
#     def __init__(self, client_id: str, client_secret: str, scope: Optional[str] = None) -> None:
#         self._client_id: str = client_id
#         self._client_secret: str = client_secret
#         self._scope: Optional[str] = scope
#
#     def get_credentials(self, url:str) -> dict:
#
#
#         session = OAuth2Session(
#             client_id=self._client_id,
#             client_secret=self._client_secret,
#             token_endpoint_auth_method="client_secret_post",
#             scope=self._scope,
#             # scope="https://graph.microsoft.com/.default",
#             token_endpoint="https://login.microsoftonline.com/c2ada19a-32ef-4a46-b125-96449efcae95/oauth2/v2.0/token",
#             grant_type="client_credentials",
#             token={"access_token": None, "expires_in": -100},
#         )
#         a = session.fetch_token()["access_token"]
#
#
# class AuthClientPassword(AuthCredentials):
#     """
#     Using username and password for authentication.
#     In case of grant type password.
#     """
#
#     def __init__(self, username: str, password: str) -> None:
#         """
#         Using username and password for authentication.
#         In case of grant type password.
#
#         Parameters
#         ----------
#         username : str
#             The username to login with.
#         password : str
#             Password fot the given User.
#         """
#
#         super().__init__()
#         self._credentials_body["grant_type"] = "password"
#         self._credentials_body["username"] = username
#         self._password_encoded = base64.b64encode(password.encode("utf-8")).decode("utf-8")
#
#     def get_credentials(self) -> dict:
#         """
#         Get decoded credentials.
#
#         Returns
#         -------
#         dict
#             Decoded credentials.
#         """
#
#         return_body = copy.deepcopy(self._credentials_body)
#         return_body["password"] = base64.b64decode(self._password_encoded.encode("utf-8")).decode(
#             "utf-8"
#         )
#         return return_body
