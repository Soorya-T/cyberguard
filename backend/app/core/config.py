"""
Application configuration module.

Provides centralized, environment-safe configuration management
with proper path resolution and sensible defaults.
"""

import logging
from pathlib import Path
from typing import Self

from pydantic import Field
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """
    Application settings with environment variable support.

    All settings can be overridden via environment variables.
    Environment variables should be prefixed with CYBERGUARD_.

    Attributes:
        app_name: Application name.
        app_version: Application version.
        debug: Debug mode flag.
        reports_dir: Directory for PDF report output.
        log_level: Logging level.
    """

    # Application metadata
    app_name: str = Field(default="CyberGuard Email Threat Intelligence API", alias="APP_NAME")
    app_version: str = Field(default="2.0.0", alias="APP_VERSION")
    debug: bool = Field(default=False, alias="DEBUG")

    # Path configuration
    reports_dir: str = Field(default="reports", alias="REPORTS_DIR")

    # Logging configuration
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # PDF configuration
    pdf_page_size: str = Field(default="A4", alias="PDF_PAGE_SIZE")
    pdf_margin_top: float = Field(default=1.0, alias="PDF_MARGIN_TOP")
    pdf_margin_bottom: float = Field(default=1.0, alias="PDF_MARGIN_BOTTOM")
    pdf_margin_left: float = Field(default=1.0, alias="PDF_MARGIN_LEFT")
    pdf_margin_right: float = Field(default=1.0, alias="PDF_MARGIN_RIGHT")

    model_config = {
        "env_prefix": "CYBERGUARD_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


class PathConfig:
    """
    Path configuration with safe resolution.

    Provides absolute paths for all application directories,
    ensuring they exist and are accessible.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        """
        Initialize path configuration.

        Args:
            settings: Application settings instance. Uses defaults if None.
        """
        self._settings = settings or Settings()
        self._base_dir = self._resolve_base_dir()
        self._reports_dir: Path | None = None

    def _resolve_base_dir(self) -> Path:
        """
        Resolve the base directory for the application.

        Returns:
            Path to the application base directory.
        """
        # Use the project root (parent of app directory)
        current_file = Path(__file__).resolve()
        # Navigate up from core -> app -> backend
        return current_file.parent.parent.parent

    @property
    def base_dir(self) -> Path:
        """Get the base directory path."""
        return self._base_dir

    @property
    def reports_dir(self) -> Path:
        """
        Get the reports directory path, creating it if necessary.

        Returns:
            Path to the reports directory.

        Raises:
            OSError: If directory creation fails.
        """
        if self._reports_dir is None:
            reports_path = self._base_dir / self._settings.reports_dir
            try:
                reports_path.mkdir(parents=True, exist_ok=True)
                self._reports_dir = reports_path
                logger.info(f"Reports directory resolved: {reports_path}")
            except OSError as e:
                logger.error(f"Failed to create reports directory: {e}")
                raise
        return self._reports_dir

    def get_pdf_path(self, filename: str) -> Path:
        """
        Get full path for a PDF file.

        Args:
            filename: Name of the PDF file.

        Returns:
            Full path to the PDF file.
        """
        return self.reports_dir / filename


# Global settings instance
_settings: Settings | None = None
_path_config: PathConfig | None = None


def get_settings() -> Settings:
    """
    Get the application settings singleton.

    Returns:
        Settings instance.
    """
    global _settings
    if _settings is None:
        _settings = Settings()
        logger.info(f"Settings loaded: app_name={_settings.app_name}, debug={_settings.debug}")
    return _settings


def get_path_config() -> PathConfig:
    """
    Get the path configuration singleton.

    Returns:
        PathConfig instance.
    """
    global _path_config
    if _path_config is None:
        _path_config = PathConfig(get_settings())
    return _path_config


def configure_logging() -> None:
    """
    Configure application-wide logging.

    Sets up logging format and level based on settings.
    """
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger.info(f"Logging configured at {settings.log_level} level")