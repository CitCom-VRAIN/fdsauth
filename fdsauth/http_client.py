import requests
from tenacity import retry, stop_after_attempt, wait_fixed
from typing import Any, Dict, Optional


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def post_request(
    url: str, data: Dict[str, Any], headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    with requests.Session() as session:
        try:
            response = session.post(url, data=data, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as http_err:
            print(
                f"HTTP error occurred: {http_err} - Status code: {response.status_code}"
            )
            raise
            return {}
        except requests.RequestException as req_err:
            print(f"Request error occurred: {req_err}")
            return {}


@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def get_request(url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    with requests.Session() as session:
        try:
            response = session.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as http_err:
            print(
                f"HTTP error occurred: {http_err} - Status code: {response.status_code}"
            )
            raise
            return {}
        except requests.RequestException as req_err:
            print(f"Request error occurred: {req_err}")
            return {}
