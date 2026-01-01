import os
import time
import logging
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta, timezone
from threading import Lock
from dataclasses import dataclass
from dotenv import load_dotenv

# --- Structured Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("BeyondTrust")

# --- Custom Exceptions ---
class BeyondTrustError(Exception):
    """Base exception for BeyondTrust Client"""
    pass

class AuthError(BeyondTrustError):
    """Raised when OAuth or Session login fails"""
    pass

class ResourceNotFoundError(BeyondTrustError):
    """Raised when a folder or secret isn't found"""
    pass

@dataclass
class ClientConfig:
    token_url: str
    sign_in_url: str
    client_id: str
    client_secret: str
    base_url: str

class BeyondTrustClient:
    """
    Thread-safe Singleton Client for BeyondTrust Password Safe API.
    Features: Automated token caching, session management, and retry logic.
    """
    _instance = None
    _lock = Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized"):
            return
            
        load_dotenv()
        self.config = self._load_config()
        self.session = requests.Session()
        
        # Token Cache
        self._access_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._token_lock = Lock()
        
        # Performance/Reliability settings
        self.retries = 3
        self.backoff = 2
        self._initialized = True
        logger.info("BeyondTrust Client initialized.")

    def _load_config(self) -> ClientConfig:
        required = ["BT_TOKEN_URL", "BT_SIGN_IN_URL", "BT_CLIENT_ID", "BT_CLIENT_SECRET", "BT_BASE_URL"]
        vals = {k: os.getenv(k) for k in required}
        missing = [k for k, v in vals.items() if not v]
        if missing:
            raise BeyondTrustError(f"Missing environment configuration: {missing}")
        return ClientConfig(**vals)

    def _refresh_token(self) -> str:
        """Fetch a new OAuth2 token with automatic retry logic."""
        payload = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "grant_type": "client_credentials",
        }
        
        for attempt in range(self.retries):
            try:
                resp = self.session.post(self.config.token_url, data=payload, timeout=10)
                resp.raise_for_status()
                data = resp.json()
                
                self._access_token = data["access_token"]
                expires_in = data.get("expires_in", 3600)
                # Buffer of 30s to prevent race conditions
                self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 30)
                
                logger.info("OAuth token refreshed successfully.")
                return self._access_token
            except Exception as e:
                if attempt == self.retries - 1:
                    raise AuthError(f"Failed to acquire token after {self.retries} attempts: {e}")
                time.sleep(self.backoff * (attempt + 1))

    def get_valid_token(self) -> str:
        """Thread-safe access to a valid OAuth token."""
        with self._token_lock:
            is_expired = self._token_expiry is None or datetime.now(timezone.utc) >= self._token_expiry
            if not self._access_token or is_expired:
                return self._refresh_token()
            return self._access_token

    def _get_auth_headers(self) -> Dict[str, str]:
        token = self.get_valid_token()
        # BeyondTrust often requires a session cookie in addition to the Bearer token
        resp = self.session.post(
            self.config.sign_in_url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=10
        )
        resp.raise_for_status()
        
        session_id = resp.cookies.get("ASP.NET_SessionId")
        if not session_id:
            raise AuthError("Authentication successful but ASP.NET_SessionId was not returned.")

        return {
            "Authorization": f"Bearer {token}",
            "Cookie": f"ASP.NET_SessionId={session_id}",
            "Accept": "application/json"
        }

    def get_secrets(self, folder_name: str) -> Dict[str, str]:
        """Retrieves all secrets within a specified folder as a Key-Value dictionary."""
        try:
            headers = self._get_auth_headers()
            
            # 1. Resolve Folder ID
            folder_resp = self.session.get(f"{self.config.base_url}/Folders", headers=headers, timeout=10)
            folder_resp.raise_for_status()
            
            folder = next((f for f in folder_resp.json() if f.get("Name") == folder_name), None)
            if not folder:
                raise ResourceNotFoundError(f"Folder '{folder_name}' not found in BeyondTrust.")

            # 2. Fetch Secrets
            f_id = folder.get("Id") or folder.get("ID")
            secrets_resp = self.session.get(f"{self.config.base_url}/Folders/{f_id}/secrets", headers=headers, timeout=10)
            secrets_resp.raise_for_status()

            return {item["Title"]: item.get("Password", "") for item in secrets_resp.json()}
            
        except requests.RequestException as e:
            logger.error(f"API Communication Error: {e}")
            raise BeyondTrustError(f"Failed to retrieve secrets: {e}")

# --- Robot Framework Entry Point ---
def get_beyondtrust_secrets(folder_name: str) -> Dict[str, str]:
    """Library keyword for Robot Framework integration."""
    return BeyondTrustClient().get_secrets(folder_name)
