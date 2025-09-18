import gradio as gr
import asyncio
import json
import time
import io
import secrets
import webbrowser
from typing import Dict, List, Any, Optional, Tuple
from PIL import Image
from urllib.parse import parse_qs, urlparse
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from auth import auth_manager, auth_session
from workflow_manager import workflow_manager
from comfy_client import comfy_client
from config import Config
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callbacks"""
    
    def do_GET(self):
        """Handle GET request for OAuth callback"""
        try:
            # Parse the URL and query parameters
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            
            if parsed_path.path == '/auth/callback':
                # Extract state and code from query parameters
                state = query_params.get('state', [None])[0]
                code = query_params.get('code', [None])[0]
                error = query_params.get('error', [None])[0]
                
                if error:
                    self.send_response(400)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(f"""
                    <html><body>
                    <h2>Authentication Error</h2>
                    <p>Error: {error}</p>
                    <p><a href="/">Return to application</a></p>
                    </body></html>
                    """.encode())
                    return
                
                if not state or not code:
                    self.send_response(400)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write("""
                    <html><body>
                    <h2>Invalid Request</h2>
                    <p>Missing state or authorization code</p>
                    <p><a href="/">Return to application</a></p>
                    </body></html>
                    """.encode())
                    return
                
                # Store callback data for the main app to process
                callback_url = f"http://localhost{self.path}"
                app_instance.handle_oauth_callback_async(callback_url)
                
                # Send success response with instructions
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write("""
                <html><body>
                <h2>Authentication Successful!</h2>
                <p>You have been signed in successfully. You can now close this tab and return to the application.</p>
                <script>
                    // Try to close the tab automatically
                    setTimeout(function() {
                        window.close();
                    }, 2000);
                </script>
                <p><a href="/">Return to application</a></p>
                </body></html>
                """.encode())
                
            else:
                # Handle other requests
                self.send_response(404)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write("""
                <html><body>
                <h2>Not Found</h2>
                <p><a href="/">Return to application</a></p>
                </body></html>
                """.encode())
                
        except Exception as e:
            logger.error(f"Error handling OAuth callback: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f"""
            <html><body>
            <h2>Server Error</h2>
            <p>Error processing request: {str(e)}</p>
            <p><a href="/">Return to application</a></p>
            </body></html>
            """.encode())
    
    def log_message(self, format, *args):
        """Suppress default HTTP server logging"""
        pass

class ComfyUIClientApp:
    def __init__(self):
        self.current_user = None
        self.current_session_id = None
        self.pending_oauth_states = {}  # Store OAuth state tokens
        self.oauth_callback_data = {}  # Store callback data
        self.callback_server = None
        self.callback_server_thread = None
        
    def start_callback_server(self):
        """Start the OAuth callback server"""
        try:
            self.callback_server = HTTPServer(('localhost', 8080), OAuthCallbackHandler)
            self.callback_server_thread = threading.Thread(
                target=self.callback_server.serve_forever,
                daemon=True
            )
            self.callback_server_thread.start()
            logger.info("OAuth callback server started on http://localhost:8080")
        except Exception as e:
            logger.error(f"Failed to start callback server: {e}")
    
    def stop_callback_server(self):
        """Stop the OAuth callback server"""
        if self.callback_server:
            self.callback_server.shutdown()
            self.callback_server = None
            logger.info("OAuth callback server stopped")
        
    def start_oauth_login(self) -> Tuple[str, str]:
        """Start Google OAuth login process."""
        if not auth_manager.client_id:
            return "Google OAuth not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your environment.", ""
        
        # Start callback server if not already running
        if not self.callback_server:
            self.start_callback_server()
        
        # Generate state token for security
        state = secrets.token_urlsafe(32)
        self.pending_oauth_states[state] = {"created_at": time.time()}
        
        # Get authorization URL
        auth_url = auth_manager.get_authorization_url(state)
        
        return f"Click the link below to sign in with Google:\n\n[Sign in with Google]({auth_url})\n\nAfter signing in, you'll be redirected back automatically.", auth_url
    
    def handle_oauth_callback_async(self, callback_url: str):
        """Handle OAuth callback asynchronously (called from callback server)"""
        try:
            message, is_logged_in, user_info = self.handle_oauth_callback(callback_url)
            # Store the result for the main app to pick up
            self.oauth_callback_data = {
                'message': message,
                'is_logged_in': is_logged_in,
                'user_info': user_info,
                'timestamp': time.time()
            }
            logger.info(f"OAuth callback processed: {message}")
        except Exception as e:
            logger.error(f"Error in async OAuth callback: {e}")
            self.oauth_callback_data = {
                'message': f"Authentication error: {str(e)}",
                'is_logged_in': False,
                'user_info': {},
                'timestamp': time.time()
            }
    
    def check_oauth_status(self) -> Tuple[str, bool, Dict[str, Any], bool]:
        """Check if OAuth callback has been processed"""
        if self.oauth_callback_data:
            data = self.oauth_callback_data
            self.oauth_callback_data = {}  # Clear after reading
            
            if data['is_logged_in']:
                workflows = self.get_workflows_for_dropdown()
                user_display = f"👤 **{data['user_info']['name']}** ({data['user_info']['email']}) - Role: {data['user_info']['role'].title()}"
                return data['message'], data['is_logged_in'], data['user_info'], True, workflows, user_display
            
            return data['message'], data['is_logged_in'], data['user_info'], True, [], ""
        
        return "", False, {}, False, [], ""
    
    def handle_oauth_callback(self, callback_url: str) -> Tuple[str, bool, Dict[str, Any]]:
        """Handle OAuth callback and complete authentication."""
        try:
            # Parse the callback URL
            parsed_url = urlparse(callback_url)
            query_params = parse_qs(parsed_url.query)
            
            if "error" in query_params:
                error = query_params["error"][0]
                return f"OAuth error: {error}", False, {}
            
            if "code" not in query_params or "state" not in query_params:
                return "Invalid callback URL. Missing authorization code or state.", False, {}
            
            code = query_params["code"][0]
            state = query_params["state"][0]
            
            # Verify state token
            if state not in self.pending_oauth_states:
                return "Invalid or expired OAuth state. Please try again.", False, {}
            
            # Clean up state token
            del self.pending_oauth_states[state]
            
            # Exchange code for tokens
            token_data = auth_manager.exchange_code_for_token(code)
            if not token_data:
                return "Failed to exchange authorization code for tokens.", False, {}
            
            # Get user information
            access_token = token_data.get("access_token")
            if not access_token:
                return "No access token received from Google.", False, {}
            
            user_info = auth_manager.get_user_info(access_token)
            if not user_info:
                return "Failed to get user information from Google.", False, {}
            
            # Verify user authorization
            is_authorized, role, reason = auth_manager.verify_user_authorization(user_info)
            if not is_authorized:
                return reason, False, {}
            
            # Create user session
            user_data = {
                "id": user_info["id"],
                "email": user_info["email"],
                "name": user_info["name"],
                "picture": user_info.get("picture", ""),
                "role": role
            }
            
            # Generate session ID and JWT token
            session_id = secrets.token_urlsafe(32)
            jwt_token = auth_manager.create_access_token(user_data)
            
            # Store session
            auth_session.create_session(session_id, user_data)
            
            # Update current user
            self.current_user = user_data
            self.current_session_id = session_id
            
            # Log successful login
            logger.info(f"User {user_data['email']} ({user_data['name']}) logged in with role: {role}")
            
            return f"Welcome, {user_data['name']}! You are signed in as {role}.", True, user_data
            
        except Exception as e:
            logger.error(f"OAuth callback error: {e}")
            return f"Authentication error: {str(e)}", False, {}
    
    def logout(self) -> Tuple[str, bool]:
        """Handle user logout."""
        if self.current_session_id:
            auth_session.delete_session(self.current_session_id)
        
        self.current_user = None
        self.current_session_id = None
        return "Logged out successfully", False
    
    def get_workflows_for_dropdown(self) -> List[str]:
        """Get workflow names for dropdown."""
        if not self.current_user:
            return []
        
        email = self.current_user['email']
        workflows = workflow_manager.get_available_workflows()
        
        # Filter workflows based on user permissions
        accessible_workflows = []
        for workflow in workflows:
            if auth_manager.can_access_workflow(email, workflow['name']):
                accessible_workflows.append(workflow['name'])
        
        return accessible_workflows
    
    def get_workflow_info(self, workflow_name: str) -> str:
        """Get workflow information and description."""
        if not workflow_name or not self.current_user:
            return "Please select a workflow"
        
        # Check permissions
        email = self.current_user['email']
        if not auth_manager.can_access_workflow(email, workflow_name):
            return "You don't have permission to access this workflow"
        
        workflows = workflow_manager.get_available_workflows()
        for workflow in workflows:
            if workflow['name'] == workflow_name:
                return f"**{workflow['display_name']}**\n\n{workflow['description']}"
        
        return "Workflow not found"
    
    def get_workflow_parameters(self, workflow_name: str) -> List[Dict[str, Any]]:
        """Get workflow parameters for dynamic form generation."""
        if not workflow_name or not self.current_user:
            return []
        
        email = self.current_user['email']
        if not auth_manager.can_access_workflow(email, workflow_name):
            return []
        
        workflows = workflow_manager.get_available_workflows()
        for workflow in workflows:
            if workflow['name'] == workflow_name:
                return workflow['parameters']
        
        return []
    
    async def execute_workflow_async(self, workflow_name: str, parameters: Dict[str, Any]) -> Tuple[str, Optional[str]]:
        """Execute workflow asynchronously."""
        if not self.current_user:
            return "Please log in first", None
        
        if not workflow_name:
            return "Please select a workflow", None
        
        email = self.current_user['email']
        if not auth_manager.can_access_workflow(email, workflow_name):
            return "You don't have permission to access this workflow", None
        
        try:
            # Validate parameters
            errors = workflow_manager.validate_parameters(workflow_name, parameters)
            if errors:
                return f"Parameter errors: {'; '.join(errors)}", None
            
            # Prepare workflow
            workflow = workflow_manager.prepare_workflow_for_execution(workflow_name, parameters)
            if not workflow:
                return "Failed to prepare workflow", None
            
            # Queue prompt
            result = await comfy_client.queue_prompt(workflow)
            if "error" in result:
                return f"Failed to queue workflow: {result['error']}", None
            
            prompt_id = result.get('prompt_id')
            if not prompt_id:
                return "No prompt ID returned", None
            
            # Wait for completion
            completion_result = await comfy_client.wait_for_completion(prompt_id)
            
            if "error" in completion_result:
                return f"Execution failed: {completion_result['error']}", None
            
            # Get output images if any
            outputs = completion_result.get('outputs', {})
            image_path = None
            
            for node_id, node_output in outputs.items():
                if 'images' in node_output:
                    images = node_output['images']
                    if images:
                        # Get the first image
                        image_info = images[0]
                        image_data = await comfy_client.get_image(
                            image_info['filename'],
                            image_info.get('subfolder', ''),
                            image_info.get('type', 'output')
                        )
                        
                        if image_data:
                            # Save image temporarily and return path
                            image = Image.open(io.BytesIO(image_data))
                            temp_path = f"temp_output_{int(time.time())}.png"
                            image.save(temp_path)
                            image_path = temp_path
                            break
            
            success_msg = f"Workflow '{workflow_name}' completed successfully!"
            if image_path:
                success_msg += f" Output image generated."
            
            # Log user activity
            logger.info(f"User {self.current_user['email']} executed workflow '{workflow_name}'")
            
            return success_msg, image_path
            
        except Exception as e:
            logger.error(f"Error executing workflow: {e}")
            return f"Error executing workflow: {str(e)}", None
    
    def execute_workflow(self, workflow_name: str, parameters: Dict[str, Any]) -> Tuple[str, Optional[str]]:
        """Synchronous wrapper for workflow execution."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.execute_workflow_async(workflow_name, parameters))

# Create app instance
app_instance = ComfyUIClientApp()

def create_interface():
    """Create the Gradio interface with Google OAuth."""
    
    with gr.Blocks(
        title=Config.APP_TITLE,
        theme=gr.themes.Soft(),
        css="""
        .auth-container { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
        .workflow-container { margin: 20px 0; }
        .parameter-section { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 10px 0; }
        .output-section { margin-top: 20px; }
        .user-info { background: #e3f2fd; padding: 10px; border-radius: 5px; margin: 10px 0; }
        """
    ) as demo:
        
        # State variables
        logged_in = gr.State(False)
        user_data = gr.State({})
        selected_workflow = gr.State("")
        
        gr.Markdown(f"# {Config.APP_TITLE}")
        gr.Markdown(Config.APP_DESCRIPTION)
        
        # Login Section
        with gr.Group(visible=True, elem_classes="auth-container") as login_section:
            gr.Markdown("## Sign In with Google")
            gr.Markdown("Please authenticate with your Google account to access ComfyUI workflows.")
            
            with gr.Row():
                start_oauth_btn = gr.Button("Start Google Sign-In", variant="primary", size="lg")
                check_status_btn = gr.Button("Check Sign-In Status", variant="secondary", size="lg")
                
            oauth_info = gr.Markdown("")
            login_status = gr.Markdown("")
        
        # Main Application (initially hidden)
        with gr.Group(visible=False) as main_section:
            # User info bar
            with gr.Row(elem_classes="user-info"):
                user_info_display = gr.Markdown("")
                with gr.Column(scale=1):
                    logout_btn = gr.Button("Sign Out", variant="secondary", size="sm")
            
            # Workflow Selection
            with gr.Group(elem_classes="workflow-container"):
                gr.Markdown("### Select Workflow")
                workflow_dropdown = gr.Dropdown(
                    label="Available Workflows",
                    choices=[],
                    value=None,
                    interactive=True
                )
                workflow_info = gr.Markdown("Please select a workflow to see details.")
                refresh_btn = gr.Button("Refresh Workflows", variant="secondary")
            
            # Dynamic Parameter Section
            with gr.Group(elem_classes="parameter-section") as param_section:
                gr.Markdown("### Workflow Parameters")
                parameters_container = gr.Column()
            
            # Execution Section
            with gr.Row():
                execute_btn = gr.Button("Execute Workflow", variant="primary", size="lg")
                interrupt_btn = gr.Button("Interrupt", variant="stop", size="lg")
            
            # Output Section
            with gr.Group(elem_classes="output-section"):
                gr.Markdown("### Execution Results")
                output_status = gr.Textbox(
                    label="Status",
                    value="Ready to execute workflow",
                    interactive=False,
                    lines=3
                )
                output_image = gr.Image(
                    label="Generated Image",
                    visible=False,
                    height=400
                )
                
                # Queue Status
                with gr.Accordion("ComfyUI Queue Status", open=False):
                    queue_info = gr.JSON(label="Current Queue Status")
                    refresh_queue_btn = gr.Button("Refresh Queue")
        
        # Event Handlers
        def handle_start_oauth():
            message, auth_url = app_instance.start_oauth_login()
            return message
        
        def handle_check_status():
            message, is_logged_in, user_info, has_update, workflows, user_display = app_instance.check_oauth_status()
            
            if has_update:
                if is_logged_in:
                    return (
                        message,  # login_status
                        gr.update(visible=False),  # login_section
                        gr.update(visible=True),   # main_section
                        gr.update(choices=workflows, value=None),  # workflow_dropdown
                        user_info,  # user_data state
                        is_logged_in,  # logged_in state
                        user_display  # user_info_display
                    )
                else:
                    return (
                        message,
                        gr.update(visible=True),
                        gr.update(visible=False),
                        gr.update(choices=[], value=None),
                        {},
                        False,
                        ""
                    )
            else:
                return (
                    "No status update available. Click 'Start Google Sign-In' first, then sign in and check status again.",
                    gr.update(),  # No change to login_section
                    gr.update(),  # No change to main_section
                    gr.update(),  # No change to workflow_dropdown
                    gr.update(),  # No change to user_data
                    gr.update(),  # No change to logged_in
                    gr.update()   # No change to user_info_display
                )
        
        def handle_logout():
            message, is_logged_in = app_instance.logout()
            return (
                message,  # login_status
                gr.update(visible=True),   # login_section
                gr.update(visible=False),  # main_section
                gr.update(choices=[], value=None),  # workflow_dropdown
                {},  # user_data
                is_logged_in,  # logged_in state
                ""  # user_info_display
            )
        
        def update_workflow_info(workflow_name):
            return app_instance.get_workflow_info(workflow_name)
        
        def refresh_workflows():
            if app_instance.current_user:
                workflows = app_instance.get_workflows_for_dropdown()
                return gr.update(choices=workflows, value=None)
            return gr.update(choices=[], value=None)
        
        def create_parameter_inputs(workflow_name):
            """Create dynamic parameter inputs based on selected workflow."""
            if not workflow_name:
                return gr.update()
            
            parameters = app_instance.get_workflow_parameters(workflow_name)
            if not parameters:
                return gr.update()
            
            # This is a simplified version - in practice, you'd need to handle
            # dynamic component creation more carefully in Gradio
            return gr.update()
        
        async def refresh_queue_status():
            """Refresh queue status."""
            try:
                queue_status = await comfy_client.get_queue_status()
                return queue_status
            except Exception as e:
                return {"error": str(e)}
        
        def execute_workflow_handler(workflow_name):
            """Handle workflow execution with current parameters."""
            if not workflow_name:
                return "Please select a workflow", gr.update(visible=False)
            
            # Get workflow parameters (in real implementation, you'd collect from dynamic form)
            # For now, using empty parameters as placeholder
            parameters = {}
            
            status, image_path = app_instance.execute_workflow(workflow_name, parameters)
            
            if image_path:
                return status, gr.update(value=image_path, visible=True)
            else:
                return status, gr.update(visible=False)
        
        async def interrupt_execution():
            """Interrupt current workflow execution."""
            try:
                success = await comfy_client.interrupt_execution()
                if success:
                    return "Execution interrupted successfully"
                else:
                    return "Failed to interrupt execution"
            except Exception as e:
                return f"Error interrupting execution: {str(e)}"
        
        # Bind events
        start_oauth_btn.click(
            handle_start_oauth,
            outputs=[oauth_info]
        )
        
        check_status_btn.click(
            handle_check_status,
            outputs=[
                login_status,
                login_section,
                main_section,
                workflow_dropdown,
                user_data,
                logged_in,
                user_info_display
            ]
        )
        
        logout_btn.click(
            handle_logout,
            outputs=[
                login_status,
                login_section,
                main_section,
                workflow_dropdown,
                user_data,
                logged_in,
                user_info_display
            ]
        )
        
        workflow_dropdown.change(
            update_workflow_info,
            inputs=[workflow_dropdown],
            outputs=[workflow_info]
        )
        
        refresh_btn.click(
            refresh_workflows,
            outputs=[workflow_dropdown]
        )
        
        execute_btn.click(
            execute_workflow_handler,
            inputs=[workflow_dropdown],
            outputs=[output_status, output_image]
        )
        
        interrupt_btn.click(
            lambda: asyncio.run(interrupt_execution()),
            outputs=[output_status]
        )
        
        refresh_queue_btn.click(
            lambda: asyncio.run(refresh_queue_status()),
            outputs=[queue_info]
        )
    
    return demo

def main():
    """Main application entry point."""
    # Clean up expired OAuth states periodically
    auth_session.cleanup_expired_sessions()
    
    demo = create_interface()
    
    # Launch the application
    demo.launch(
        server_name=Config.GRADIO_HOST,
        server_port=Config.GRADIO_PORT,
        share=False,
        debug=True,
        auth=None  # We handle auth ourselves
    )

if __name__ == "__main__":
    main()