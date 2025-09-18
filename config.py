import os
from typing import Dict, List

class Config:
    # ComfyUI Server Configuration
    COMFYUI_SERVER_HOST = os.getenv("COMFYUI_SERVER_HOST", "127.0.0.1")
    COMFYUI_SERVER_PORT = os.getenv("COMFYUI_SERVER_PORT", "8188")
    COMFYUI_BASE_URL = f"http://{COMFYUI_SERVER_HOST}:{COMFYUI_SERVER_PORT}"
    
    # Authentication
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    
    # Application Settings
    APP_TITLE = "ComfyUI Workflow Client"
    APP_DESCRIPTION = "Employee interface for ComfyUI workflows"
    WORKFLOWS_DIR = "workflows"
    
    # Gradio Settings
    GRADIO_HOST = os.getenv("GRADIO_HOST", "0.0.0.0")
    GRADIO_PORT = int(os.getenv("GRADIO_PORT", "7860"))
    
    # User Database (In production, use a real database)
    USERS_DB = {
        "admin": {
            "username": "admin",
            "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # secret
            "role": "admin",
            "full_name": "Administrator"
        },
        "employee1": {
            "username": "employee1",
            "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # secret
            "role": "employee",
            "full_name": "John Doe"
        }
    }
    
    # Workflow permissions (which users can access which workflows)
    WORKFLOW_PERMISSIONS = {
        "admin": ["*"],  # Admin can access all workflows
        "employee1": ["text_generation", "image_processing"]  # Employee can access specific workflows
    }