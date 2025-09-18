import os
import json
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from urllib.parse import urlencode
import requests
from jose import JWTError, jwt
from config import Config
import logging

logger = logging.getLogger(__name__)

class GoogleOAuthManager:
    def __init__(self):
        self.client_id = Config.GOOGLE_CLIENT_ID
        self.client_secret = Config.GOOGLE_CLIENT_SECRET
        self.redirect_uri = Config.GOOGLE_REDIRECT_URI
        self.secret_key = Config.SECRET_KEY
        self.algorithm = Config.ALGORITHM
        
        # Google OAuth 2.0 endpoints
        self.auth_url = "https://accounts.google.com/o/oauth2/auth"
        self.token_url = "https://oauth2.googleapis.com/token"
        self.userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        
        # OAuth scopes
        self.scopes = ["openid", "email", "profile"]
        
        if not self.client_id or not self.client_secret:
            logger.error("Google OAuth credentials not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")
    
    def get_authorization_url(self, state: str = None) -> str:
        """Generate Google OAuth authorization URL."""
        if state is None:
            state = secrets.token_urlsafe(32)
        
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "response_type": "code",
            "access_type": "offline",
            "state": state,
            "prompt": "select_account"
        }
        
        return f"{self.auth_url}?{urlencode(params)}"
    
    def exchange_code_for_token(self, code: str) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access token."""
        try:
            data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": self.redirect_uri
            }
            
            response = requests.post(self.token_url, data=data)
            response.raise_for_status()
            
            return response.json()
        
        except requests.RequestException as e:
            logger.error(f"Error exchanging code for token: {e}")
            return None
    
    def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user information from Google API."""
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(self.userinfo_url, headers=headers)
            response.raise_for_status()
            
            return response.json()
        
        except requests.RequestException as e:
            logger.error(f"Error getting user info: {e}")
            return None
    
    def verify_user_authorization(self, user_info: Dict[str, Any]) -> tuple[bool, str, str]:
        """
        Verify if user is authorized to access the system.
        Returns: (is_authorized, role, reason)
        """
        email = user_info.get("email", "").lower()
        name = user_info.get("name", "")
        
        if not email:
            return False, "", "No email address found in Google account"
        
        if not Config.is_authorized_user(email):
            return False, "", f"User {email} is not authorized to access this system"
        
        role = Config.get_user_role(email)
        if role == "admin":
            return True, "admin", f"Admin access granted for {email}"
        elif role == "employee":
            return True, "employee", f"Employee access granted for {email}"
        else:
            return False, "", f"User {email} has no valid role assigned"
    
    def create_access_token(self, user_data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token for the authenticated user."""
        to_encode = {
            "sub": user_data["email"],  # Use email as subject
            "google_id": user_data["id"],  # Keep Google ID for reference
            "email": user_data["email"],
            "name": user_data["name"],
            "role": user_data["role"],
            "picture": user_data.get("picture", "")
        }
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            email = payload.get("sub")
            
            if email is None:
                return None
            
            # Check if user is still authorized (in case permissions changed)
            if not Config.is_authorized_user(email):
                return None
            
            return payload
        
        except JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            return None
    
    def get_user_permissions(self, email: str) -> list:
        """Get workflow permissions for a user."""
        return Config.get_user_permissions(email)
    
    def can_access_workflow(self, email: str, workflow_name: str) -> bool:
        """Check if user can access a specific workflow."""
        permissions = self.get_user_permissions(email)
        return "*" in permissions or workflow_name in permissions

class AuthSession:
    """Simple session management for storing auth states."""
    
    def __init__(self):
        self.sessions = {}
    
    def create_session(self, session_id: str, user_data: Dict[str, Any]) -> None:
        """Create a new session."""
        self.sessions[session_id] = {
            "user_data": user_data,
            "created_at": datetime.utcnow(),
            "last_activity": datetime.utcnow()
        }
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data."""
        session = self.sessions.get(session_id)
        if session:
            # Update last activity
            session["last_activity"] = datetime.utcnow()
            return session["user_data"]
        return None
    
    def delete_session(self, session_id: str) -> None:
        """Delete a session."""
        self.sessions.pop(session_id, None)
    
    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> None:
        """Remove expired sessions."""
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        expired_sessions = [
            sid for sid, session in self.sessions.items()
            if session["last_activity"] < cutoff
        ]
        
        for sid in expired_sessions:
            del self.sessions[sid]

# Global instances
auth_manager = GoogleOAuthManager()
auth_session = AuthSession()