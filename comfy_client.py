import asyncio
import aiohttp
import json
import uuid
import websockets
import time
from typing import Dict, Any, Optional, List
from config import Config
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ComfyUIClient:
    def __init__(self):
        self.base_url = Config.COMFYUI_BASE_URL
        self.client_id = str(uuid.uuid4())
        
    async def get_object_info(self) -> Dict[str, Any]:
        """Get information about all available nodes."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/object_info") as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logger.error(f"Failed to get object info: {response.status}")
                        return {}
        except Exception as e:
            logger.error(f"Error getting object info: {e}")
            return {}
    
    async def get_embeddings(self) -> List[str]:
        """Get list of available embeddings."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/embeddings") as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return []
        except Exception as e:
            logger.error(f"Error getting embeddings: {e}")
            return []
    
    async def get_models(self, model_type: str) -> List[str]:
        """Get list of available models for a specific type."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/models/{model_type}") as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return []
        except Exception as e:
            logger.error(f"Error getting models for {model_type}: {e}")
            return []
    
    async def queue_prompt(self, prompt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Queue a prompt for execution."""
        try:
            prompt_request = {
                "prompt": prompt,
                "client_id": self.client_id
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/prompt",
                    json=prompt_request,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.info(f"Queued prompt with ID: {result.get('prompt_id')}")
                        return result
                    else:
                        error_data = await response.json()
                        logger.error(f"Failed to queue prompt: {error_data}")
                        return {"error": error_data}
        except Exception as e:
            logger.error(f"Error queuing prompt: {e}")
            return {"error": str(e)}
    
    async def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/prompt") as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {}
        except Exception as e:
            logger.error(f"Error getting queue status: {e}")
            return {}
    
    async def get_history(self, prompt_id: Optional[str] = None) -> Dict[str, Any]:
        """Get execution history."""
        try:
            url = f"{self.base_url}/history"
            if prompt_id:
                url += f"/{prompt_id}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {}
        except Exception as e:
            logger.error(f"Error getting history: {e}")
            return {}
    
    async def get_image(self, filename: str, subfolder: str = "", folder_type: str = "output") -> Optional[bytes]:
        """Download an image from ComfyUI."""
        try:
            params = {
                "filename": filename,
                "type": folder_type
            }
            if subfolder:
                params["subfolder"] = subfolder
            
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/view", params=params) as response:
                    if response.status == 200:
                        return await response.read()
                    else:
                        logger.error(f"Failed to get image {filename}: {response.status}")
                        return None
        except Exception as e:
            logger.error(f"Error getting image {filename}: {e}")
            return None
    
    async def wait_for_completion(self, prompt_id: str, timeout: int = 300) -> Dict[str, Any]:
        """Wait for a prompt to complete execution."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                history = await self.get_history(prompt_id)
                if prompt_id in history:
                    result = history[prompt_id]
                    if result.get("status", {}).get("completed", False):
                        logger.info(f"Prompt {prompt_id} completed successfully")
                        return result
                    elif "error" in result.get("status", {}):
                        logger.error(f"Prompt {prompt_id} failed: {result['status']['error']}")
                        return result
                
                await asyncio.sleep(2)  # Wait 2 seconds before checking again
                
            except Exception as e:
                logger.error(f"Error checking completion status: {e}")
                await asyncio.sleep(2)
        
        logger.error(f"Timeout waiting for prompt {prompt_id} to complete")
        return {"error": "Timeout waiting for completion"}
    
    async def interrupt_execution(self, prompt_id: Optional[str] = None) -> bool:
        """Interrupt current execution."""
        try:
            data = {}
            if prompt_id:
                data["prompt_id"] = prompt_id
                
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.base_url}/interrupt", json=data) as response:
                    return response.status == 200
        except Exception as e:
            logger.error(f"Error interrupting execution: {e}")
            return False

# Global client instance
comfy_client = ComfyUIClient()