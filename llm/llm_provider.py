"""
llm_provider.py — Groq LLM Provider (Phase 3+)

Initializes the ChatGroq model using the GROK_API_KEY from the .env file.
Provides a central singleton for the agent's reasoning nodes.
"""

import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq

# Load environment variables from the project root .env
load_dotenv()

_api_key = os.getenv("GROK_API_KEY")

if not _api_key:
    raise ValueError(
        "[ERROR] GROK_API_KEY not found in environment. "
        "Ensure a .env file exists in the project root with GROK_API_KEY=<your-key>."
    )

# Initialize ChatGroq with deterministic output for security reasoning
llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    groq_api_key=_api_key,
    temperature=0,
)


def get_llm():
    """Returns the initialized Groq LLM instance."""
    return llm
