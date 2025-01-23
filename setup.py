from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of your README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="fdsauth",
    version="0.0.6",
    author="Joan Ciprià",
    author_email="joamoteo@upv.es",
    description="Python authentication for FIWARE Data Space",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CitCom-VRAIN/fdsauth",
    packages=find_packages(),
    install_requires=["requests", "tenacity", "jwt"],
)
