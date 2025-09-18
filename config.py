import os
from typing import Dict, List

class Config:
    # ComfyUI Server Configuration
    COMFYUI_SERVER_HOST = os.getenv("COMFYUI_SERVER_HOST", "127.0.0.1")
    COMFYUI_SERVER_PORT = os.getenv("COMFYUI_SERVER_PORT", "8188")
    COMFYUI_BASE_URL = f"http://{COMFYUI_SERVER_HOST}:{COMFYUI_SERVER_PORT}"
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
    # Updated to use port 8080 for the callback server
    GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8080/auth/callback")
    
    # Authentication
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours
    
    # Application Settings
    APP_TITLE = "ComfyUI Workflow Client"
    APP_DESCRIPTION = "Employee interface for ComfyUI workflows"
    WORKFLOWS_DIR = "workflows"
    
    # Gradio Settings
    GRADIO_HOST = os.getenv("GRADIO_HOST", "0.0.0.0")
    GRADIO_PORT = int(os.getenv("GRADIO_PORT", "7860"))
    
    # Admin Email Addresses (Replace with actual admin emails)
    ADMIN_EMAILS = [
        "admin@company.com",
        "manager@company.com",
        "cto@company.com",
        # Add more admin email addresses here
    ]
    
    # Employee Email Addresses with their workflow permissions
    EMPLOYEE_PERMISSIONS = {
        "employee1@company.com": ["text_generation", "image_processing"],
        "employee2@company.com": ["simple_text"],
        "designer@company.com": ["image_processing", "art_generation"],
        "writer@company.com": ["text_generation", "content_creation"],
        # Add more employees and their permissions here
    }
    
    # Optional: Domain-based access (if you want to allow all users from certain domains)
    ALLOWED_DOMAINS = [
        # "company.com",  # Uncomment and add your company domain
        # "trusted-partner.com",  # Add trusted partner domains
    ]
    
    @classmethod
    def get_user_permissions(cls, email: str) -> List[str]:
        """Get workflow permissions for a user email."""
        if cls.is_admin(email):
            return ["*"]  # Admin access to all workflows
        return cls.EMPLOYEE_PERMISSIONS.get(email, [])
    
    @classmethod
    def is_admin(cls, email: str) -> bool:
        """Check if an email address is an admin."""
        return email.lower() in [admin_email.lower() for admin_email in cls.ADMIN_EMAILS]
    
    @classmethod
    def is_authorized_user(cls, email: str) -> bool:
        """Check if an email address is authorized to use the system."""
        email_lower = email.lower()
        
        # Check if user is explicitly listed as admin
        if cls.is_admin(email):
            return True
        
        # Check if user is explicitly listed as employee
        if email_lower in [emp_email.lower() for emp_email in cls.EMPLOYEE_PERMISSIONS.keys()]:
            return True
        
        # Check if user's domain is in allowed domains
        if cls.ALLOWED_DOMAINS:
            user_domain = email_lower.split('@')[-1]
            if user_domain in [domain.lower() for domain in cls.ALLOWED_DOMAINS]:
                return True
        
        return False
    
    @classmethod
    def get_user_role(cls, email: str) -> str:
        """Get user role based on email."""
        if cls.is_admin(email):
            return "admin"
        elif email.lower() in [emp_email.lower() for emp_email in cls.EMPLOYEE_PERMISSIONS.keys()]:
            return "employee"
        elif cls.ALLOWED_DOMAINS:
            user_domain = email.lower().split('@')[-1]
            if user_domain in [domain.lower() for domain in cls.ALLOWED_DOMAINS]:
                return "employee"  # Domain users get employee role by default
        return "unauthorized"