"""
tool_wrapper.py — Authentication Decorator for SOC Agent Tools

Provides the @requires_auth decorator that enforces JWT validation
before any protected tool is allowed to execute.
"""

import functools
from typing import Callable, Any

from identity_provider import validate_token, TokenValidationError


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class UnauthorizedToolCallError(Exception):
    """
    Raised when a tool call is blocked because the supplied JWT is
    missing, invalid, expired, or does not authorise the target tool.
    """


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------


def requires_auth(func: Callable) -> Callable:
    """
    Decorator that gates any tool function behind JWT validation.

    Contract:
        - The decorated function MUST accept ``token: str`` as its first
          positional argument.
        - The token is validated against both the JWT signature/expiry
          and the ``allowed_tools`` claim embedded in the token.

    On success:
        Executes the wrapped tool and logs an [AUTH] success line.

    On failure:
        Raises ``UnauthorizedToolCallError`` with a clear denial message
        that includes the tool name and the underlying reason.

    Args:
        func: The tool function to protect.

    Returns:
        A wrapper function with identical call signature.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        tool_name: str = func.__name__

        # ------------------------------------------------------------------
        # Extract the token — it must be the first positional argument.
        # ------------------------------------------------------------------
        if not args:
            raise UnauthorizedToolCallError(
                f"[AUTH DENIED] Tool '{tool_name}' requires a token as its first argument, "
                "but none was provided."
            )

        token: str = args[0]

        # ------------------------------------------------------------------
        # Validate the token.
        # ------------------------------------------------------------------
        try:
            payload = validate_token(token, tool_name)
        except TokenValidationError as exc:
            raise UnauthorizedToolCallError(
                f"[AUTH DENIED] Attempted to call '{tool_name}' — blocked. Reason: {exc}"
            ) from exc

        # ------------------------------------------------------------------
        # Execute the tool.
        # ------------------------------------------------------------------
        result = func(*args, **kwargs)

        agent_id: str = payload.get("agent_id", "unknown-agent")
        print(f"[AUTH] Agent {agent_id} called {tool_name} successfully")

        return result

    return wrapper
