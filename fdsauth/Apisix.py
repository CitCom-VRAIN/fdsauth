import logging
from fdsauth.http_client import get_request, post_request
import jwt
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)


class Apisix:
    def __init__(self, protocol, apisix_endpoint):
        self.protocol = protocol
        self.apisix_endpoint = apisix_endpoint
        self.token_endpoint = self.get_token_endpoint()

    def get_token_endpoint(self):
        """Fetch the token endpoint from the Apisix configuration."""
        url = (
            f"{self.protocol}://{self.apisix_endpoint}/.well-known/openid-configuration"
        )
        logger.info("Fetching data service access token")
        response_data = get_request(url)
        token_endpoint = response_data.get("token_endpoint")
        return token_endpoint

    def get_data_service_access_token(self, token_endpoint, vp_token) -> str:
        """Fetch a data service access token using the VP token."""

        if (
            hasattr(self, "data_service_access_token")
            and self.data_service_access_token
        ):
            try:
                decoded_token = jwt.decode(
                    self.data_service_access_token, options={"verify_signature": False}
                )
                exp_timestamp = decoded_token.get("exp")
                if (
                    exp_timestamp
                    and datetime.fromtimestamp(exp_timestamp) > datetime.now()
                ):
                    return self.data_service_access_token
            except jwt.ExpiredSignatureError:
                logger.info("Token has expired, fetching a new one.")
            except jwt.DecodeError:
                logger.error("Failed to decode token, fetching a new one.")

        data = {"grant_type": "vp_token", "vp_token": vp_token, "scope": "default"}
        response_data = post_request(token_endpoint, data)
        self.data_service_access_token = response_data.get("access_token")
        return self.data_service_access_token
