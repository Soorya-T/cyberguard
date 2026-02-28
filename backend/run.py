"""
Development Server Entry Point
==============================

This script provides a clean entry point for running the FastAPI development
server with proper exception handling for Windows.

Usage:
    python run.py              # Development mode with reload
    python run.py --no-reload  # Development mode without reload

This script suppresses the asyncio.CancelledError traceback that occurs on Windows
when using uvicorn with --reload by setting PYTHONPATH to include the backend
directory, which causes usercustomize.py to be loaded in the subprocess.
"""

import sys
import os
import argparse

# Get the backend directory path
backend_dir = os.path.dirname(os.path.abspath(__file__))

# Set PYTHONPATH to include backend directory so usercustomize.py is loaded
# in the uvicorn reloader subprocess
current_pythonpath = os.environ.get('PYTHONPATH', '')
if backend_dir not in current_pythonpath:
    if current_pythonpath:
        os.environ['PYTHONPATH'] = f"{backend_dir}{os.pathsep}{current_pythonpath}"
    else:
        os.environ['PYTHONPATH'] = backend_dir

# Now import and apply the patch for this process too
import asyncio
import multiprocessing

if sys.platform == 'win32':
    _original_bootstrap = multiprocessing.process.BaseProcess._bootstrap
    
    def _patched_bootstrap(self, *args, **kwargs):
        try:
            _original_bootstrap(self, *args, **kwargs)
        except (KeyboardInterrupt, asyncio.CancelledError, SystemExit):
            sys.exit(0)
        except BaseException:
            raise
    
    multiprocessing.process.BaseProcess._bootstrap = _patched_bootstrap


def main():
    """Run the development server."""
    import uvicorn
    from app.core.config import settings
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Run the CyberGuard development server")
    parser.add_argument(
        "--no-reload",
        action="store_true",
        help="Disable auto-reload",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to (default: 8000)",
    )
    args = parser.parse_args()
    
    print(f"\n{'='*50}")
    print(f"  {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"  Environment: {settings.ENVIRONMENT}")
    print(f"{'='*50}\n")
    
    if args.no_reload:
        print("Running without auto-reload")
    else:
        print("Running with auto-reload enabled")
    
    print(f"Server: http://{args.host}:{args.port}")
    print("Press CTRL+C to stop\n")
    
    # Run uvicorn
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=not args.no_reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
