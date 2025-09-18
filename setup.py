#!/usr/bin/env python3
"""
Setup script for ComfyUI Client Application
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def run_command(command):
    """Run a command and return its output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running command: {command}")
            print(f"Error: {result.stderr}")
            return False
        return True
    except Exception as e:
        print(f"Exception running command {command}: {e}")
        return False

def create_directory_structure():
    """Create the required directory structure."""
    directories = [
        "workflows",
        "static",
        "temp"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"Created directory: {directory}")

def create_env_file():
    """Create .env file with default configuration."""
    env_content = """# ComfyUI Client Configuration
COMFYUI_SERVER_HOST=127.0.0.1
COMFYUI_SERVER_PORT=8188
SECRET_KEY=your-secret-key-change-this-in-production
GRADIO_HOST=0.0.0.0
GRADIO_PORT=7860
"""
    
    with open(".env", "w") as f:
        f.write(env_content)
    print("Created .env file with default configuration")

def install_dependencies():
    """Install Python dependencies."""
    print("Installing Python dependencies...")
    
    if not run_command("pip install -r requirements.txt"):
        print("Failed to install dependencies")
        return False
    
    print("Dependencies installed successfully")
    return True

def create_sample_workflows():
    """Create sample workflow files if they don't exist."""
    # The workflow files are already created in the artifacts above
    # This function can be used to copy them or create additional samples
    
    sample_workflows = {
        "simple_text.json": {
            "display_name": "Simple Text Processing",
            "description": "A simple workflow for text processing tasks",
            "parameters": [
                {
                    "name": "input_text",
                    "display_name": "Input Text",
                    "type": "textarea",
                    "default_value": "Hello, world!",
                    "description": "Text to process",
                    "required": True
                }
            ],
            "workflow": {
                "1": {
                    "inputs": {
                        "text": "@input_text"
                    },
                    "class_type": "TextProcessor",
                    "outputs": ["TEXT"]
                }
            }
        }
    }
    
    for filename, workflow_data in sample_workflows.items():
        filepath = Path("workflows") / filename
        if not filepath.exists():
            with open(filepath, "w") as f:
                json.dump(workflow_data, f, indent=2)
            print(f"Created sample workflow: {filename}")

def setup_authentication():
    """Setup initial authentication data."""
    print("\n=== Authentication Setup ===")
    print("Default users:")
    print("- Username: admin, Password: secret (Role: admin)")
    print("- Username: employee1, Password: secret (Role: employee)")
    print("\nTo change passwords, edit config.py and hash new passwords with:")
    print("from passlib.context import CryptContext")
    print("pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')")
    print("hashed = pwd_context.hash('your_new_password')")

def main():
    """Main setup function."""
    print("=== ComfyUI Client Setup ===\n")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    
    # Create directory structure
    print("1. Creating directory structure...")
    create_directory_structure()
    
    # Create environment file
    print("\n2. Creating configuration file...")
    create_env_file()
    
    # Install dependencies
    print("\n3. Installing dependencies...")
    if not install_dependencies():
        print("Setup failed during dependency installation")
        sys.exit(1)
    
    # Create sample workflows
    print("\n4. Creating sample workflows...")
    create_sample_workflows()
    
    # Setup authentication info
    setup_authentication()
    
    print("\n=== Setup Complete ===")
    print("\nNext steps:")
    print("1. Make sure ComfyUI is running on http://127.0.0.1:8188")
    print("2. Place your workflow JSON files in the 'workflows' directory")
    print("3. Edit config.py to customize users and permissions")
    print("4. Run the application with: python app.py")
    print("\nThe application will be available at: http://localhost:7860")

if __name__ == "__main__":
    main()