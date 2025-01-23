# Python Authentication for FIWARE Data Space (FDSAuth) ![PyPI - Version](https://img.shields.io/pypi/v/fdsauth) ![package workflow](https://github.com/CitCom-VRAIN/fdsauth/actions/workflows/package.yml/badge.svg)
**FDSAuth** helps developers implement secure and reliable FIWARE Data Space Connector authentication in their applications.

## Table of Contents 📚
- [Python Authentication for FIWARE Data Space (FDSAuth)  ](#python-authentication-for-fiware-data-space-fdsauth--)
  - [Table of Contents 📚](#table-of-contents-)
  - [Installation 🛠️](#installation-️)
  - [Usage  💻](#usage--)
  - [Development 🚀](#development-)
  - [Contact 📫](#contact-)
  - [Acknowledgments 🙏](#acknowledgments-)

## Installation 🛠️
To install FDSAuth, simply use `pip`:

```bash
pip install fdsauth
```

## Usage  💻
First a DID (Decentralized Identifier) and the corresponding key-material is required. You can create such via:
```bash
mkdir certs && cd certs
docker run -v $(pwd):/cert quay.io/wi_stefan/did-helper:0.1.1
```
Usage example:
```python
from fdsauth import Consumer
import requests

consumer = Consumer(
    keycloak_protocol="http",
    keycloak_endpoint="keycloak.consumer-a.local",
    keycloak_realm_path="realms/test-realm/protocol",
    keycloak_user_name="test-user",
    keycloak_user_password="test",
    apisix_protocol="http",
    apisix_endpoint="apisix-proxy.provider-a.local",
    certs_path="./certs",
)

try:
    # Attempt to access data using the obtained service token. Get entities of type EnergyReport.
    url = f"http://apisix-proxy.provider-a.local/ngsi-ld/v1/entities?type=EnergyReport"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {consumer.get_data_service_access_token()}",
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    print(response.json())
except Exception as req_err:
    print(f"Request error occurred: {req_err}")
```

## Development 🚀
```bash
# Create virtual env
python3 -m venv ./venv && source ./venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Build
python setup.py sdist bdist_wheel

# Local testing
pip install dist/fdsauth-X.X.X-py3-none-any.whl
```

## Contact 📫
For any questions or support, please reach out to us via GitHub Issues or email us at [joamoteo@upv.es](mailto:joamoteo@upv.es).

## Acknowledgments 🙏
This work has been made by **VRAIN** for the **CitCom.ai** project, co-funded by the EU.

<img src="https://vrain.upv.es/wp-content/uploads/2022/01/vrain_1920_1185.jpg" alt="VRAIN" width="200"/>
<img src="https://www.fiware.org/wp-content/directories/research-development/images/citcom-ai.png" alt="CitCom.ai" width="200"/>
