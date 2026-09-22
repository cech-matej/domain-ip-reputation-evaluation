"""
Application Configuration
=========================

This module contains all configuration used by the application.
Values may come from environment variables (.env) or default values.

Sections:
    - Mock API configuration
    - External API keys
    - Network configuration
    - Application settings

Add new configuration sections as needed.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()


def env(key: str, default=None):
    """
    Helper function to read environment variables
    with optional defaults.
    """
    return os.getenv(key, default)


# ============================================================
# MOCK API CONFIGURATION
# ============================================================
# Settings used by the internal mock API server.

MOCK_API_HOST: str = env("MOCK_API_HOST", "127.0.0.1")
MOCK_API_PORT: int = int(env("MOCK_API_PORT", 5000))
MOCK_API_BASE: str = f"http://{MOCK_API_HOST}:{MOCK_API_PORT}"
USE_MOCK_API: bool = env("USE_MOCK_API", "false").lower() == "true"


# ============================================================
# EXTERNAL API KEYS
# ============================================================
# API keys for external threat intelligence services.

ABUSEIPDB_API_KEY: str | None = env("ABUSEIPDB_API_KEY")

CLOUDFLARE_RADAR_API_KEY: str | None = env("CLOUDFLARE_RADAR_API_KEY")
CLOUDFLARE_USERID: str | None = env("CLOUDFLARE_USERID")

CRIMINALIP_API_KEY: str | None = env("CRIMINALIP_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY: str = env("GOOGLE_SAFE_BROWSING_API_KEY")
GREYNOISE_API_KEY: str | None = env("GREYNOISE_API_KEY")
GRIFFINGUARD_API_KEY: str | None = env("GRIFFINGUARD_API_KEY")
HYBRID_ANALYSIS_API_KEY: str | None = env("HYBRID_ANALYSIS_API_KEY")
NERD_API_KEY: str | None = env("NERD_API_KEY")
OPENTIP_KASPERSKY_API_KEY: str | None = env("OPENTIP_KASPERSKY_API_KEY")
OTX_ALIENVAULT_API_KEY: str | None = env("OTX_ALIENVAULT_API_KEY")
PHISHING_INITIATIVE_API_KEY: str | None = env("PHISHING_INITIATIVE_API_KEY")
PULSEDIVE_API_KEY: str | None = env("PULSEDIVE_API_KEY")
THREATFOX_API_KEY: str | None = env("THREATFOX_API_KEY")
VIRUSTOTAL_API_KEY: str | None = env("VIRUSTOTAL_API_KEY")
WHOISXML_DOMAIN_REPUTATION_API_KEY: str | None = env("WHOISXML_DOMAIN_REPUTATION_API_KEY")


# ============================================================
# NETWORK SETTINGS
# ============================================================
# Global HTTP/network behavior.
# Currently not used by the application, but defined here for future use.

HTTP_TIMEOUT: int = int(env("HTTP_TIMEOUT", 10))
HTTP_RETRIES: int = int(env("HTTP_RETRIES", 3))

# ============================================================
# COLLECTOR SETTINGS
# ============================================================

ENABLE_CACHE: bool = env("ENABLE_CACHE", "true").lower() == "true"
RESUME_COLLECTION: bool = env("RESUME_COLLECTION", "true").lower() == "true"
SAVE_PROGRESS: bool = env("SAVE_PROGRESS", "true").lower() == "true"
