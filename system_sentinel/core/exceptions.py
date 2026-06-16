from __future__ import annotations


class SentinelError(Exception):
    """Base exception for all SystemSentinel errors."""


class ConfigError(SentinelError):
    """Raised when config.yaml is missing, unreadable, or fails validation."""


class ToolError(SentinelError):
    """Raised when a tool encounters an unrecoverable execution error."""


class ToolPermissionError(ToolError):
    """Raised when a tool lacks the required OS permissions to run."""


class MonitorError(SentinelError):
    """Raised when a monitor cannot collect a metric."""


class ChatAdapterError(SentinelError):
    """Raised when a chat adapter cannot connect or authenticate."""


class ChatAuthError(ChatAdapterError):
    """Raised when a chat adapter rejects credentials."""


class LLMUnavailableError(SentinelError):
    """Raised when an LLM provider cannot be reached."""


class DatabaseError(SentinelError):
    """Raised when a database operation fails."""


class SetupError(SentinelError):
    """Raised when the setup wizard encounters a fatal error."""
