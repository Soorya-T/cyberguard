"""
Site Customization for Windows
==============================

This module is automatically loaded by Python at startup (when PYTHONPATH includes
this directory). It patches multiprocessing to suppress CancelledError tracebacks
that occur when using uvicorn with --reload on Windows.

This is a workaround for: https://github.com/encode/uvicorn/issues/1574
"""

import sys
import multiprocessing
import asyncio


def _patch_multiprocessing_for_windows():
    """
    Patch multiprocessing.process.BaseProcess._bootstrap to suppress
    CancelledError/KeyboardInterrupt tracebacks on Windows.
    
    These tracebacks are a known issue with uvicorn's reloader on Windows
    and are harmless - they just look ugly.
    """
    if sys.platform != 'win32':
        return
    
    # Only patch once
    if hasattr(multiprocessing.process.BaseProcess, '_cyberguard_patched'):
        return
    
    original_bootstrap = multiprocessing.process.BaseProcess._bootstrap
    
    def patched_bootstrap(self, *args, **kwargs):
        try:
            original_bootstrap(self, *args, **kwargs)
        except (KeyboardInterrupt, asyncio.CancelledError, SystemExit):
            # Silently exit on these expected shutdown exceptions
            sys.exit(0)
        except Exception:
            # Re-raise other exceptions with full traceback
            raise
    
    multiprocessing.process.BaseProcess._bootstrap = patched_bootstrap
    multiprocessing.process.BaseProcess._cyberguard_patched = True


# Apply the patch when this module is loaded
_patch_multiprocessing_for_windows()
