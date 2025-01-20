import os
import requests
import json
import logging
from base64 import urlsafe_b64encode
from subprocess import run, CalledProcessError
from tenacity import retry, stop_after_attempt, wait_fixed
from typing import Optional, Dict, Any

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

        self.session = requests.Session()

    def _construct_url(self, path: str) -> str:
        return f"{self.protocol}://{self.keycloak_endpoint}/{self.keycloak_realm_path}/{path}"

    def _post_request(
        self, url: str, data: Dict[str, Any], headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        try:
            response = self.session.post(url, data=data, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"POST request to {url} failed: {e}")
            raise

    def _get_request(
        self, url: str, headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        try:
            response = self.session.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"GET request to {url} failed: {e}")
            raise

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
        response_data = self._post_request(url, data)
        self.access_token = response_data.get("access_token")
        return self.access_token

    def get_offer_uri(self) -> str:
        """Fetch the offer URI for a user credential."""
        url = self._construct_url(
            "oid4vc/credential-offer-uri?credential_configuration_id=user-credential"
        )
        headers = {"Authorization": f"Bearer {self.access_token}"}
        logger.info("Fetching offer URI")
        offer_data = self._get_request(url, headers)
        self.offer_uri = f"{offer_data.get('issuer')}{offer_data.get('nonce')}"
        return self.offer_uri

    def get_pre_authorized_code(self) -> str:
        """Retrieve a pre-authorized code from the offer URI."""
        headers = {"Authorization": f"Bearer {self.access_token}"}
        logger.info("Retrieving pre-authorized code")
        grants = self._get_request(self.offer_uri, headers).get("grants", {})
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
        response_data = self._post_request(url, data)
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
        response_data = self._post_request(url, data, headers)
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
            os.makedirs(self.certs_path, exist_ok=True)
            try:
                run(
                    [
                        "docker",
                        "run",
                        "-v",
                        f"{os.getcwd()}/{self.certs_path}:/cert",
                        "quay.io/wi_stefan/did-helper:0.1.1",
                    ],
                    check=True,
                )
            except CalledProcessError:
                logger.error("Failed to generate certificates.")
                raise RuntimeError("Failed to generate certificates.")
            os.chmod(f"{self.certs_path}/private-key.pem", 0o644)

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
        return run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-binary",
                "-sign",
                f"{self.certs_path}/private-key.pem",
            ],
            input=data.encode(),
            capture_output=True,
            check=True,
        ).stdout

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def get_data_service_access_token(self) -> str:
        """Fetch a data service access token using the VP token."""
        url = f"{self.protocol}://{self.gateway_endpoint}/.well-known/openid-configuration"
        logger.info("Fetching data service access token")
        token_endpoint = self._get_request(url).get("token_endpoint")

        data = {"grant_type": "vp_token", "vp_token": self.vp_token, "scope": "default"}
        try:
            response_data = self._post_request(token_endpoint, data)
            self.data_service_access_token = response_data.get("access_token")
            return self.data_service_access_token
        except requests.exceptions.HTTPError as e:
            logger.error(
                f"Failed to fetch data service access token: {e.response.text}"
            )
            raise
