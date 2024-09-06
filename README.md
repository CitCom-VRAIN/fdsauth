# fdsauth
Python authentication for FIWARE Data Space

## Installation
In your project folder run:
```bash
pip install fdsauth
```

## Usage
First, define following environment variables in your `.env` file. Substitute example values for your own:
```bash
KEYCLOAK_PROTOCOL=http
KEYCLOAK_ENDPOINT=keycloak-consumer.127.0.0.1.nip.io:8080
KEYCLOAK_USERNAME=test-user
KEYCLOAK_PASSWORD=test
```

Usage example:
```python
from dotenv import load_dotenv
from fdsauth import Consumer

# Load environment variables from .env file
load_dotenv()

# Create a Consumer instance and retrieve the verifiable credential
consumer = Consumer()
jwt_credential = consumer.get_auth_token()
print(jwt_credential)
```

## Development
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