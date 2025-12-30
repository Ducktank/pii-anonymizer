"""
LLM Client Module
Handles API calls to Claude (and optionally other LLMs).
"""

import os
from typing import Optional, Generator
from dotenv import load_dotenv

load_dotenv()


class LLMClient:
    """Unified LLM client supporting Claude and OpenAI."""
    
    def __init__(self, provider: str = "claude", model: Optional[str] = None):
        self.provider = provider
        
        if provider == "claude":
            self.model = model or "claude-sonnet-4-20250514"
            self._init_claude()
        elif provider == "openai":
            self.model = model or "gpt-4o"
            self._init_openai()
        else:
            raise ValueError(f"Unknown provider: {provider}")
    
    def _init_claude(self):
        """Initialize Anthropic client."""
        try:
            from anthropic import Anthropic
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not set in environment")
            self.client = Anthropic(api_key=api_key)
        except ImportError:
            raise ImportError("Please install anthropic: pip install anthropic")
    
    def _init_openai(self):
        """Initialize OpenAI client."""
        try:
            from openai import OpenAI
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OPENAI_API_KEY not set in environment")
            self.client = OpenAI(api_key=api_key)
        except ImportError:
            raise ImportError("Please install openai: pip install openai")
    
    def chat(
        self, 
        message: str, 
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096
    ) -> str:
        """Send a message and get a response."""
        
        if self.provider == "claude":
            return self._chat_claude(message, system_prompt, max_tokens)
        elif self.provider == "openai":
            return self._chat_openai(message, system_prompt, max_tokens)
    
    def _chat_claude(
        self, 
        message: str, 
        system_prompt: Optional[str],
        max_tokens: int
    ) -> str:
        """Chat via Claude API."""
        kwargs = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": message}]
        }
        
        if system_prompt:
            kwargs["system"] = system_prompt
        
        response = self.client.messages.create(**kwargs)
        return response.content[0].text
    
    def _chat_openai(
        self, 
        message: str, 
        system_prompt: Optional[str],
        max_tokens: int
    ) -> str:
        """Chat via OpenAI API."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": message})
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens
        )
        return response.choices[0].message.content
    
    def stream_chat(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096
    ) -> Generator[str, None, None]:
        """Stream a chat response."""
        
        if self.provider == "claude":
            yield from self._stream_claude(message, system_prompt, max_tokens)
        elif self.provider == "openai":
            yield from self._stream_openai(message, system_prompt, max_tokens)
    
    def _stream_claude(
        self,
        message: str,
        system_prompt: Optional[str],
        max_tokens: int
    ) -> Generator[str, None, None]:
        """Stream via Claude API."""
        kwargs = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": message}]
        }
        
        if system_prompt:
            kwargs["system"] = system_prompt
        
        with self.client.messages.stream(**kwargs) as stream:
            for text in stream.text_stream:
                yield text
    
    def _stream_openai(
        self,
        message: str,
        system_prompt: Optional[str],
        max_tokens: int
    ) -> Generator[str, None, None]:
        """Stream via OpenAI API."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": message})
        
        stream = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            stream=True
        )
        
        for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content


class MockLLMClient:
    """Mock client for testing without API keys."""
    
    def __init__(self):
        self.provider = "mock"
        self.model = "mock-model"
    
    def chat(
        self, 
        message: str, 
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096
    ) -> str:
        """Return a mock response that echoes back placeholders."""
        return f"""I received your message about the patient. Here's my analysis:

The patient [PERSON_1] presents with the symptoms you described. Based on the information from their medical record, I would recommend:

1. Follow up with [PERSON_1] regarding their current treatment plan
2. Contact them at [PHONE_NUMBER_1] or [EMAIL_ADDRESS_1] to schedule an appointment
3. Review their history at your facility

Please let me know if you need any additional information about this case."""
    
    def stream_chat(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096
    ) -> Generator[str, None, None]:
        """Stream mock response."""
        response = self.chat(message, system_prompt, max_tokens)
        # Simulate streaming by yielding word by word
        for word in response.split(" "):
            yield word + " "


def get_client(provider: str = "claude", mock: bool = False) -> LLMClient:
    """Factory function to get appropriate LLM client."""
    if mock:
        return MockLLMClient()
    return LLMClient(provider=provider)


if __name__ == "__main__":
    # Test with mock client
    client = get_client(mock=True)
    response = client.chat("Test message about patient John Smith")
    print("Mock response:")
    print(response)
