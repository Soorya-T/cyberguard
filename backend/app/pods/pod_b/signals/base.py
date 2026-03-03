"""
CyberGuard Pod B - Signal Base Module

This module defines the abstract base class for all signal detection modules.
Every signal must inherit from BaseSignal and implement the analyze() method.

This ensures:
- Consistent interface across all signals
- Type safety for inputs and outputs
- Proper error handling and isolation
- Standardized logging and metrics
- Easy extensibility for new signals
"""

from __future__ import annotations

from datetime import datetime
from typing import List
from pydantic import BaseModel
import time
from abc import ABC, abstractmethod
from typing import Any, ClassVar, Dict, Optional, Type

from app.core.config import get_settings
from app.core.logging import get_logger, SignalLogger
from app.models.models import (
    ParsedEmail,
    Severity,
    SignalResult,
    SignalMetadata,
    Verdict,
)


class SignalError(Exception):
    """Base exception for signal-related errors."""
    pass


class SignalTimeoutError(SignalError):
    """Raised when a signal exceeds its timeout limit."""
    pass


class SignalValidationError(SignalError):
    """Raised when signal input validation fails."""
    pass


class BaseSignal(ABC):
    """
    Abstract base class for all signal detection modules.
    
    All signal modules must inherit from this class and implement
    the analyze() method. This ensures a consistent interface
    across all detection modules.
    
    Class Attributes:
        name: Unique identifier for the signal (UPPER_SNAKE_CASE)
        description: Human-readable description of what the signal detects
        version: Signal version for tracking changes
        weight: Weight multiplier for scoring (default: 1.0)
        requires: List of email fields required for this signal
    
    Example:
        >>> class MySignal(BaseSignal):
        ...     name = "MY_SIGNAL"
        ...     description = "Detects my threat"
        ...
        ...     def analyze(self, email: ParsedEmail) -> SignalResult:
        ...         # Detection logic here
        ...         return SignalResult(
        ...             signal=self.name,
        ...             score=0,
        ...             severity=Severity.LOW,
        ...             reason="No threat detected"
        ...         )
    """
    
    # Class-level attributes (must be overridden in subclasses)
    name: ClassVar[str]
    description: ClassVar[str]
    version: ClassVar[str] = "1.0.0"
    weight: ClassVar[float] = 1.0
    requires: ClassVar[List[str]] = []
    
    def __init__(self, settings: Optional[Any] = None):
        """
        Initialize the signal.
        
        Args:
            settings: Optional settings override. Uses global settings if None.
        """
        self.settings = settings or get_settings()
        self._logger = SignalLogger(self.name if hasattr(self, 'name') else self.__class__.__name__)
        self._log = get_logger(f"signal.{self.__class__.__name__.lower()}")
    
    def evaluate(self, email: ParsedEmail) -> SignalResult:
        """
        Execute the signal analysis with error handling and logging.
        
        This method wraps the analyze() method with:
        - Input validation
        - Error isolation
        - Execution timing
        - Structured logging
        
        Args:
            email: Parsed email to analyze
        
        Returns:
            SignalResult with analysis outcome
        
        Note:
            This method should NOT be overridden. Override analyze() instead.
        """
        start_time = time.perf_counter()
        email_id = email.email_id
        
        self._logger.log_start(email_id)
        
        # Validate input
        validation_error = self._validate_input(email)
        if validation_error:
            self._log.warning(
                "signal_validation_failed",
                signal=self.name,
                email_id=email_id,
                reason=validation_error
            )
            return self._create_error_result(
                f"Validation failed: {validation_error}"
            )
        
        try:
            # Execute analysis
            result = self.analyze(email)
            
            # Apply weight
            weighted_score = int(result.score * self.weight)
            weighted_score = min(weighted_score, 100)  # Cap at 100
            
            # Update result with weighted score
            result.score = weighted_score
            
            # Add execution time
            duration_ms = (time.perf_counter() - start_time) * 1000
            result.execution_time_ms = round(duration_ms, 2)
            
            self._logger.log_complete(
                email_id,
                result.score,
                result.severity.value,
                duration_ms
            )
            
            return result
            
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            self._logger.log_error(email_id, e, duration_ms)
            
            return self._create_error_result(
                f"Signal analysis failed: {str(e)}"
            )
    
    @abstractmethod
    def analyze(self, email: ParsedEmail) -> SignalResult:
        """
        Analyze the email for this signal's specific threat.
        
        This method must be implemented by all signal subclasses.
        It should contain the core detection logic.
        
        Args:
            email: Parsed email to analyze
        
        Returns:
            SignalResult with detection outcome
        
        Note:
            - Do NOT raise exceptions; return error results instead
            - Use self._log for logging within this method
            - Access configuration via self.settings
        """
        raise NotImplementedError("Subclasses must implement analyze()")
    
    def _validate_input(self, email: ParsedEmail) -> Optional[str]:
        """
        Validate that the email has all required fields for this signal.
        
        Override this method to add custom validation logic.
        
        Args:
            email: Parsed email to validate
        
        Returns:
            None if valid, error message string if invalid
        """
        for field in self.requires:
            value = getattr(email, field, None)
            if value is None or (isinstance(value, str) and not value):
                return f"Missing required field: {field}"
        return None
    
    def _create_error_result(self, error_message: str) -> SignalResult:
        """
        Create a SignalResult for error conditions.
        
        Args:
            error_message: Description of the error
        
        Returns:
            SignalResult with error information
        """
        return SignalResult(
            signal=self.name,
            score=0,
            severity=Severity.LOW,
            reason=f"Error: {error_message}",
            confidence=0.0,
        )
    
    def _create_result(
        self,
        score: int,
        severity: Severity,
        reason: str,
        metadata: Optional[SignalMetadata] = None,
        confidence: float = 1.0
    ) -> SignalResult:
        """
        Helper to create a properly formatted SignalResult.
        
        Args:
            score: Risk score (0-100)
            severity: Severity level
            reason: Human-readable explanation
            metadata: Additional context
            confidence: Confidence level (0.0-1.0)
        
        Returns:
            SignalResult instance
        """
        return SignalResult(
            signal=self.name,
            score=min(max(score, 0), 100),  # Clamp to 0-100
            severity=severity,
            reason=reason,
            metadata=metadata or SignalMetadata(),
            confidence=confidence,
        )
    
    @classmethod
    def get_info(cls) -> Dict[str, Any]:
        """
        Get information about this signal.
        
        Returns:
            Dictionary with signal metadata
        """
        return {
            "name": cls.name,
            "description": cls.description,
            "version": cls.version,
            "weight": cls.weight,
            "requires": cls.requires,
        }


class SignalRegistry:
    """
    Registry for signal modules.
    
    Provides a central point for registering and discovering signals.
    This enables dynamic signal loading and configuration.
    
    Example:
        >>> @SignalRegistry.register
        ... class MySignal(BaseSignal):
        ...     name = "MY_SIGNAL"
        ...     ...
        
        >>> # Get all registered signals
        >>> signals = SignalRegistry.get_all_signals()
    """
    
    _signals: Dict[str, Type[BaseSignal]] = {}
    
    @classmethod
    def register(cls, signal_class: Type[BaseSignal]) -> Type[BaseSignal]:
        """
        Register a signal class.
        
        Args:
            signal_class: The signal class to register
        
        Returns:
            The registered signal class (for decorator use)
        """
        if not hasattr(signal_class, 'name'):
            raise ValueError(f"Signal {signal_class.__name__} must have a 'name' attribute")
        
        cls._signals[signal_class.name] = signal_class
        return signal_class
    
    @classmethod
    def get_signal(cls, name: str) -> Optional[Type[BaseSignal]]:
        """
        Get a signal class by name.
        
        Args:
            name: Signal name (UPPER_SNAKE_CASE)
        
        Returns:
            Signal class or None if not found
        """
        return cls._signals.get(name)
    
    @classmethod
    def get_all_signals(cls) -> List[Type[BaseSignal]]:
        """
        Get all registered signal classes.
        
        Returns:
            List of signal classes
        """
        return list(cls._signals.values())
    
    @classmethod
    def get_signal_names(cls) -> List[str]:
        """
        Get all registered signal names.
        
        Returns:
            List of signal names
        """
        return list(cls._signals.keys())
    
    @classmethod
    def clear(cls) -> None:
        """Clear all registered signals (for testing)."""
        cls._signals.clear()


def create_signal_result(
    signal_name: str,
    score: int,
    severity: Severity,
    reason: str,
    **metadata: Any
) -> SignalResult:
    """
    Convenience function to create a SignalResult.
    
    Args:
        signal_name: Name of the signal
        score: Risk score (0-100)
        severity: Severity level
        reason: Human-readable explanation
        **metadata: Additional metadata fields
    
    Returns:
        SignalResult instance
    """
    meta = SignalMetadata()
    for key, value in metadata.items():
        if hasattr(meta, key):
            setattr(meta, key, value)
        else:
            meta.raw_evidence[key] = value
    
    return SignalResult(
        signal=signal_name,
        score=score,
        severity=severity,
        reason=reason,
        metadata=meta,
    )
class ScanResult(BaseModel):
    email_id: str
    tenant_id: str
    email_hash: str
 
    verdict: Verdict 
    total_score: int
    confidence: float

    manager_summary: str
    action_recommended: str

    signals: List[SignalResult]

    scan_duration_ms: float
    scanned_at: datetime
    version: str