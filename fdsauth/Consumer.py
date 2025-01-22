import os
import json
import logging
from base64 import urlsafe_b64encode
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from fdsauth.http_client import post_request, get_request

logger = logging.getLogger(__name__)


class Consumer:
    def __init__(
        self,
        protocol: str,
        keycloak_endpoint: str,
        keycloak_realm_path: str,
        keycloak_user_name: str,
        keycloak_user_password: str,
        gateway_endpoint: str,
        certs_path: str,
    ):
        self.protocol = protocol
        self.keycloak_endpoint = keycloak_endpoint
        self.keycloak_realm_path = keycloak_realm_path
        self.keycloak_user_name = keycloak_user_name
        self.keycloak_user_password = keycloak_user_password
        self.gateway_endpoint = gateway_endpoint
        self.certs_path = certs_path

        self.access_token: Optional[str] = None
        self.offer_uri: Optional[str] = None
        self.pre_authorized_code: Optional[str] = None
        self.credential_access_token: Optional[str] = None
        self.verifiable_credential: Optional[str] = None
        self.holder_did: Optional[str] = None
        self.jwt: Optional[str] = None
        self.vp_token: Optional[str] = None
        self.data_service_access_token: Optional[str] = None

    def _construct_url(self, path: str) -> str:
        return f"{self.protocol}://{self.keycloak_endpoint}/{self.keycloak_realm_path}/{path}"

    def get_access_token(self) -> str:
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
        self.access_token = response_data.get("access_token")
        return self.access_token

    def get_offer_uri(self) -> str:
        """Fetch the offer URI for a user credential."""
        url = self._construct_url(
            "oid4vc/credential-offer-uri?credential_configuration_id=user-credential"
        )
        headers = {"Authorization": f"Bearer {self.access_token}"}
        logger.info("Fetching offer URI")
        offer_data = get_request(url, headers)
        self.offer_uri = f"{offer_data.get('issuer')}{offer_data.get('nonce')}"
        return self.offer_uri

    def get_pre_authorized_code(self) -> str:
        """Retrieve a pre-authorized code from the offer URI."""
        headers = {"Authorization": f"Bearer {self.access_token}"}
        logger.info("Retrieving pre-authorized code")
        grants = get_request(self.offer_uri, headers).get("grants", {})
        self.pre_authorized_code = grants.get(
            "urn:ietf:params:oauth:grant-type:pre-authorized_code", {}
        ).get("pre-authorized_code")
        return self.pre_authorized_code

    def get_credential_access_token(self) -> str:
        """Obtain a credential access token using the pre-authorized code."""
        url = self._construct_url("openid-connect/token")
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": self.pre_authorized_code,
        }
        logger.info("Requesting credential access token")
        response_data = post_request(url, data)
        self.credential_access_token = response_data.get("access_token")
        return self.credential_access_token

    def get_verifiable_credential(self) -> str:
        """Fetch the verifiable credential in JWT format."""
        url = self._construct_url("oid4vc/credential")
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.credential_access_token}",
        }
        data = json.dumps(
            {"credential_identifier": "user-credential", "format": "jwt_vc"}
        )
        logger.info("Fetching verifiable credential")
        response_data = post_request(url, data, headers)
        self.verifiable_credential = response_data.get("credential")
        return self.verifiable_credential

    def encode_vp_token(self) -> str:
        """Create a VP token from the verifiable credential."""
        self._ensure_certs_path_exists()
        self._load_holder_did()

        presentation = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [self.verifiable_credential],
            "holder": self.holder_did,
        }

        jwt_header = self._encode_json(
            {"alg": "ES256", "typ": "JWT", "kid": self.holder_did}
        )
        payload = self._encode_json(
            {"iss": self.holder_did, "sub": self.holder_did, "vp": presentation}
        )
        data_to_sign = f"{jwt_header}.{payload}"

        signature = self._sign_data(data_to_sign)
        signature_b64 = urlsafe_b64encode(signature).decode().rstrip("=")
        self.jwt = f"{jwt_header}.{payload}.{signature_b64}"
        self.vp_token = urlsafe_b64encode(self.jwt.encode()).decode().rstrip("=")
        return self.vp_token

    def _ensure_certs_path_exists(self) -> None:
        if not os.path.exists(self.certs_path):
            raise FileNotFoundError(
                f"Certificate path {self.certs_path} does not exist"
            )

    def _load_holder_did(self) -> None:
        try:
            with open(f"{self.certs_path}/did.json", "r") as f:
                self.holder_did = json.load(f).get("id")
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Failed to read holder DID: {e}")
            raise

    def _encode_json(self, data: Dict[str, Any]) -> str:
        return urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    def _sign_data(self, data: str) -> bytes:
        with open(f"{self.certs_path}/private-key.pem", "rb") as key_file:
            private_key = load_pem_private_key(key_file.read(), password=None)

        # Hash the data
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data.encode())
        hashed_data = digest.finalize()

        # Sign the hashed data
        signature = private_key.sign(hashed_data, ec.ECDSA(Prehashed(hashes.SHA256())))
        return signature

    def get_data_service_access_token(self) -> str:
        """Fetch a data service access token using the VP token."""
        url = f"{self.protocol}://{self.gateway_endpoint}/.well-known/openid-configuration"
        logger.info("Fetching data service access token")
        token_endpoint = get_request(url).get("token_endpoint")

        data = {"grant_type": "vp_token", "vp_token": self.vp_token, "scope": "default"}
        response_data = post_request(token_endpoint, data)
        self.data_service_access_token = response_data.get("access_token")
        return self.data_service_access_token
