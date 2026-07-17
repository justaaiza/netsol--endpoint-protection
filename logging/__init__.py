"""
Project 'logging' package.

NOTE: This folder shadows the stdlib 'logging' module by name.
The stdlib collision is handled in app.py (loaded into sys.modules before
any third-party imports). This file exists only to make `logging/` a Python
package so that `logging.audit_logger` can be loaded via importlib.

Do NOT add imports here — it will run before app.py's collision fix.
"""
