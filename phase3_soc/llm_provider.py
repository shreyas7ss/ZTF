"""
llm_provider.py — Groq LLM Provider for Phase 3 SOC Agent

Initializes the ChatGroq model using the GROK_API_KEY from the .env file.
Provides a central interface for the agent's reasoning nodes.
"""

import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq

# Load environment variables from .env
load_dotenv()

# The user specified the variable as GROK_API_KEY
_api_key = os.getenv("GROK_API_KEY")

if not _api_key:
    raise ValueError("[ERROR] GROK_API_KEY not found in environment. Please check your .env file.")

# Initialize the Groq Chat Model
# Using Llama 3.3 70B Versatile for high-quality SOC reasoning
llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    groq_api_key=_api_key,
    temperature=0,  # Deterministic output for security reasoning
)


def get_llm():
    """
    Returns the initialized Groq LLM instance.
    """
    return llm
