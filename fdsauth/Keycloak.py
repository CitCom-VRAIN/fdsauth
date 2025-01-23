import logging
import json
from fdsauth.http_client import post_request, get_request

# Configure logging
logger = logging.getLogger(__name__)


class Keycloak:
    def __init__(
        self,
        protocol: str,
        keycloak_endpoint: str,
        keycloak_realm_path: str,
        keycloak_user_name: str,
        keycloak_user_password: str,
    ):
        self.protocol = protocol
        self.keycloak_endpoint = keycloak_endpoint
        self.keycloak_realm_path = keycloak_realm_path
        self.keycloak_user_name = keycloak_user_name
        self.keycloak_user_password = keycloak_user_password

    def get_credential(self) -> dict:
        access_token = self._get_access_token()
        offer_uri = self._get_offer_uri(access_token)
        pre_authorized_code = self._get_pre_authorized_code(access_token, offer_uri)
        credential_access_token = self._get_credential_access_token(pre_authorized_code)
        self.verifiable_credential = self._get_verifiable_credential(
            credential_access_token
        )
        return self.verifiable_credential

    def _construct_url(self, path: str) -> str:
        return f"{self.protocol}://{self.keycloak_endpoint}/{self.keycloak_realm_path}/{path}"

    def _get_access_token(self) -> str:
        """Obtain an access token from Keycloak."""
        url = self._construct_url("openid-connect/token")
        data = {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": self.keycloak_user_name,
            "password": self.keycloak_user_password,
        }
        logger.info("Requesting access token from Keycloak")
        response_data = post_request(url, data)
        access_token = response_data.get("access_token")
        return access_token

    def _get_offer_uri(self, access_token) -> str:
        """Fetch the offer URI for a user credential."""
        url = self._construct_url(
            "oid4vc/credential-offer-uri?credential_configuration_id=user-credential"
        )
        headers = {"Authorization": f"Bearer {access_token}"}
        logger.info("Fetching offer URI")
        offer_data = get_request(url, headers)
        offer_uri = f"{offer_data.get('issuer')}{offer_data.get('nonce')}"
        return offer_uri

    def _get_pre_authorized_code(self, access_token, offer_uri) -> str:
        """Retrieve a pre-authorized code from the offer URI."""
        headers = {"Authorization": f"Bearer {access_token}"}
        logger.info("Retrieving pre-authorized code")
        grants = get_request(offer_uri, headers).get("grants", {})
        pre_authorized_code = grants.get(
            "urn:ietf:params:oauth:grant-type:pre-authorized_code", {}
        ).get("pre-authorized_code")
        return pre_authorized_code

    def _get_credential_access_token(self, pre_authorized_code) -> str:
        """Obtain a credential access token using the pre-authorized code."""
        url = self._construct_url("openid-connect/token")
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": pre_authorized_code,
        }
        logger.info("Requesting credential access token")
        response_data = post_request(url, data)
        credential_access_token = response_data.get("access_token")
        return credential_access_token

    def _get_verifiable_credential(self, credential_access_token) -> str:
        """Fetch the verifiable credential in JWT format."""
        url = self._construct_url("oid4vc/credential")
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {credential_access_token}",
        }
        data = json.dumps(
            {"credential_identifier": "user-credential", "format": "jwt_vc"}
        )
        logger.info("Fetching verifiable credential")
        response_data = post_request(url, data, headers)
        verifiable_credential = response_data.get("credential")
        return verifiable_credential
