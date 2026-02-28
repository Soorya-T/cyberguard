"""
User Customization for Windows
==============================

This module is automatically loaded by Python at startup when PYTHONPATH includes
this directory. It patches multiprocessing to suppress CancelledError tracebacks
that occur when using uvicorn with --reload on Windows.

To use this, set PYTHONPATH to include the backend directory:
    set PYTHONPATH=C:\CyberGuard_AI\cyberguard\backend
    uvicorn app.main:app --reload

Or use the run.py script which handles this automatically.
"""

import sys
import asyncio


def _patch_multiprocessing_for_uvicorn():
    """
    Patch multiprocessing.process.BaseProcess._bootstrap to suppress
    CancelledError/KeyboardInterrupt tracebacks on Windows.
    """
    if sys.platform != 'win32':
        return
    
    try:
        import multiprocessing.process
    except ImportError:
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
        except BaseException:
            # Re-raise other exceptions with full traceback
            raise
    
    multiprocessing.process.BaseProcess._bootstrap = patched_bootstrap
    multiprocessing.process.BaseProcess._cyberguard_patched = True


# Apply the patch when this module is loaded
_patch_multiprocessing_for_uvicorn()
