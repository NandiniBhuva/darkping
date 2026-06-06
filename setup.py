from setuptools import setup, find_packages

setup(
    name="darkping",
    version="0.1.0",
    description="Attacker's eye view of your domain — OSINT + AI correlation engine",
    author="Nandini Bhuva",
    packages=find_packages(),
    install_requires=[
        "rich>=13.0.0",
        "requests>=2.28.0",
        "dnspython>=2.3.0",
        "groq>=0.4.0",
    ],
    entry_points={
        "console_scripts": [
            "darkping=darkping.cli:main",
        ],
    },
    python_requires=">=3.9",
)
