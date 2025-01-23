import os
import logging
from fdsauth.Keycloak import Keycloak
from fdsauth.Apisix import Apisix
from fdsauth.credentials_utils import get_vp_token

logger = logging.getLogger(__name__)


class Consumer:
    def __init__(
        self,
        keycloak_protocol: str,
        keycloak_endpoint: str,
        keycloak_realm_path: str,
        keycloak_user_name: str,
        keycloak_user_password: str,
        apisix_protocol: str,
        apisix_endpoint: str,
        certs_path: str,
    ):
        # Initialize Keycloak client
        self.keycloak = Keycloak(
            keycloak_protocol,
            keycloak_endpoint,
            keycloak_realm_path,
            keycloak_user_name,
            keycloak_user_password,
        )

        # Get verifiable credential
        self.verifiable_credential = self.keycloak.get_credential()

        # Initialize Apisix client
        self.apisix = Apisix(apisix_protocol, apisix_endpoint)

        # Get VP Token
        self.vp_token = get_vp_token(self.verifiable_credential, certs_path)

    def get_data_service_access_token(self):
        return self.apisix.get_data_service_access_token(
            self.apisix.token_endpoint, self.vp_token
        )
