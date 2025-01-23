import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from base64 import urlsafe_b64encode
import logging
from typing import Optional, Dict, Any

# Configure logging
logger = logging.getLogger(__name__)


def get_vp_token(verifiable_credential, certs_path) -> str:
    """Create a VP token from the verifiable credential."""
    _ensure_certs_path_exists(certs_path)
    holder_did = _load_holder_did(certs_path)

    presentation = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [verifiable_credential],
        "holder": holder_did,
    }

    jwt_header = _encode_json({"alg": "ES256", "typ": "JWT", "kid": holder_did})
    payload = _encode_json({"iss": holder_did, "sub": holder_did, "vp": presentation})
    data_to_sign = f"{jwt_header}.{payload}"

    signature = _sign_data(data_to_sign, certs_path)
    signature_b64 = urlsafe_b64encode(signature).decode().rstrip("=")
    jwt = f"{jwt_header}.{payload}.{signature_b64}"
    vp_token = urlsafe_b64encode(jwt.encode()).decode().rstrip("=")
    return vp_token


def _ensure_certs_path_exists(certs_path) -> None:
    if not os.path.exists(certs_path):
        raise FileNotFoundError(f"Certificate path {certs_path} does not exist")


def _load_holder_did(certs_path) -> None:
    try:
        with open(f"{certs_path}/did.json", "r") as f:
            holder_did = json.load(f).get("id")
            return holder_did
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"Failed to read holder DID: {e}")
        raise


def _encode_json(data: Dict[str, Any]) -> str:
    return urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def _sign_data(data: str, certs_path) -> bytes:
    with open(f"{certs_path}/private-key.pem", "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None)

    # Hash the data
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    hashed_data = digest.finalize()

    # Sign the hashed data
    signature = private_key.sign(hashed_data, ec.ECDSA(Prehashed(hashes.SHA256())))
    return signature
