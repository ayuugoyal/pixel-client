import json
import os
import re
from typing import Dict, List, Any, Optional
from config import Config
import logging

logger = logging.getLogger(__name__)

class WorkflowManager:
    def __init__(self):
        self.workflows_dir = Config.WORKFLOWS_DIR
        self.ensure_workflows_dir()
        
    def ensure_workflows_dir(self):
        """Ensure workflows directory exists."""
        if not os.path.exists(self.workflows_dir):
            os.makedirs(self.workflows_dir)
            
    def get_available_workflows(self, username: str = None) -> List[Dict[str, Any]]:
        """Get list of available workflows for a user."""
        workflows = []
        
        if not os.path.exists(self.workflows_dir):
            return workflows
            
        for filename in os.listdir(self.workflows_dir):
            if filename.endswith('.json'):
                workflow_name = filename[:-5]  # Remove .json extension
                
                # Check permissions if username provided
                if username:
                    from auth import auth_manager
                    if not auth_manager.can_access_workflow(username, workflow_name):
                        continue
                
                try:
                    workflow_data = self.load_workflow(workflow_name)
                    if workflow_data:
                        workflows.append({
                            'name': workflow_name,
                            'display_name': workflow_data.get('display_name', workflow_name.replace('_', ' ').title()),
                            'description': workflow_data.get('description', 'No description available'),
                            'parameters': self.extract_workflow_parameters(workflow_data)
                        })
                except Exception as e:
                    logger.error(f"Error loading workflow {workflow_name}: {e}")
                    
        return workflows
    
    def load_workflow(self, workflow_name: str) -> Optional[Dict[str, Any]]:
        """Load a workflow from file."""
        filepath = os.path.join(self.workflows_dir, f"{workflow_name}.json")
        
        if not os.path.exists(filepath):
            logger.error(f"Workflow file not found: {filepath}")
            return None
            
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading workflow {workflow_name}: {e}")
            return None
    
    def save_workflow(self, workflow_name: str, workflow_data: Dict[str, Any]) -> bool:
        """Save a workflow to file."""
        filepath = os.path.join(self.workflows_dir, f"{workflow_name}.json")
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(workflow_data, f, indent=2, ensure_ascii=False)
            logger.info(f"Saved workflow: {workflow_name}")
            return True
        except Exception as e:
            logger.error(f"Error saving workflow {workflow_name}: {e}")
            return False
    
    def extract_workflow_parameters(self, workflow_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract configurable parameters from workflow."""
        parameters = []
        
        # Look for parameters in workflow metadata
        if 'parameters' in workflow_data:
            return workflow_data['parameters']
        
        # Extract from workflow nodes (for ComfyUI workflows)
        workflow = workflow_data.get('workflow', {})
        
        for node_id, node_data in workflow.items():
            node_class = node_data.get('class_type', '')
            inputs = node_data.get('inputs', {})
            
            # Look for common parameter patterns
            for input_name, input_value in inputs.items():
                # Skip if it's a connection to another node
                if isinstance(input_value, list):
                    continue
                    
                # Check for marked parameters (starting with @)
                if isinstance(input_value, str) and input_value.startswith('@'):
                    param_name = input_value[1:]  # Remove @ prefix
                    
                    parameter = {
                        'name': param_name,
                        'display_name': param_name.replace('_', ' ').title(),
                        'type': 'text',
                        'default_value': '',
                        'node_id': node_id,
                        'input_name': input_name
                    }
                    
                    # Try to infer parameter type from node class and input name
                    parameter['type'] = self.infer_parameter_type(node_class, input_name, input_value)
                    
                    parameters.append(parameter)
        
        return parameters
    
    def infer_parameter_type(self, node_class: str, input_name: str, input_value: Any) -> str:
        """Infer parameter type from node information."""
        # Text/prompt inputs
        if any(keyword in input_name.lower() for keyword in ['text', 'prompt', 'string']):
            if 'positive' in input_name.lower() or 'negative' in input_name.lower():
                return 'textarea'
            return 'text'
        
        # Numeric inputs
        if any(keyword in input_name.lower() for keyword in ['steps', 'cfg', 'scale', 'seed', 'width', 'height', 'strength']):
            return 'number'
        
        # Boolean inputs
        if any(keyword in input_name.lower() for keyword in ['enable', 'disable', 'toggle']):
            return 'checkbox'
        
        # File inputs
        if any(keyword in input_name.lower() for keyword in ['image', 'mask', 'file']):
            return 'file'
        
        # Default to text
        return 'text'
    
    def prepare_workflow_for_execution(self, workflow_name: str, parameters: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Prepare workflow for execution by substituting parameters."""
        workflow_data = self.load_workflow(workflow_name)
        if not workflow_data:
            return None
        
        # Clone workflow to avoid modifying original
        workflow = json.loads(json.dumps(workflow_data.get('workflow', {})))
        
        # Substitute parameters
        for node_id, node_data in workflow.items():
            inputs = node_data.get('inputs', {})
            
            for input_name, input_value in inputs.items():
                # Check for parameter placeholders
                if isinstance(input_value, str) and input_value.startswith('@'):
                    param_name = input_value[1:]
                    if param_name in parameters:
                        # Replace with actual parameter value
                        inputs[input_name] = parameters[param_name]
                        logger.info(f"Substituted {param_name}: {parameters[param_name]}")
        
        return workflow
    
    def validate_parameters(self, workflow_name: str, parameters: Dict[str, Any]) -> List[str]:
        """Validate workflow parameters."""
        errors = []
        workflow_data = self.load_workflow(workflow_name)
        
        if not workflow_data:
            errors.append("Workflow not found")
            return errors
        
        workflow_params = self.extract_workflow_parameters(workflow_data)
        
        # Check for required parameters
        for param in workflow_params:
            param_name = param['name']
            param_type = param['type']
            
            if param_name not in parameters:
                if param.get('required', True):
                    errors.append(f"Required parameter '{param_name}' is missing")
                continue
            
            value = parameters[param_name]
            
            # Type validation
            if param_type == 'number':
                try:
                    float(value)
                except (ValueError, TypeError):
                    errors.append(f"Parameter '{param_name}' must be a number")
            
            elif param_type == 'checkbox':
                if not isinstance(value, bool):
                    errors.append(f"Parameter '{param_name}' must be a boolean")
        
        return errors

# Global workflow manager instance
workflow_manager = WorkflowManager()