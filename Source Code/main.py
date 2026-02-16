"""
SAS Network Diagnostics Tool
Entry point — configures logging, resolves asset paths, and launches the app.

Copyright 2026 Southern Automation Solutions
"""

import logging
import os
import sys
import traceback


def setup_logging():
    """Configure logging with file and console handlers."""
    log_dir = os.path.join(os.path.expanduser("~"), ".sas-netdiag")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "netdiag.log")

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s  %(levelname)-8s  %(name)-25s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    # Suppress noisy third-party loggers
    logging.getLogger("PIL").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return log_file


def main():
    log_file = setup_logging()
    logger = logging.getLogger("main")
    logger.info("=" * 60)
    logger.info("SAS Network Diagnostics Tool starting")
    logger.info(f"Log file: {log_file}")
    logger.info(f"Python: {sys.version}")
    logger.info(f"Frozen: {getattr(sys, 'frozen', False)}")

    try:
        from app import App

        app = App()
        logger.info("Application window created, entering main loop")
        app.mainloop()
    except Exception:
        logger.critical("Fatal error:\n" + traceback.format_exc())
        # Show error dialog if possible
        try:
            import tkinter as tk
            from tkinter import messagebox

            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "SAS Network Diagnostics — Fatal Error",
                f"The application encountered a fatal error.\n\n"
                f"Details have been written to:\n{log_file}\n\n"
                f"Please send this file to Contact@SASControls.com",
            )
            root.destroy()
        except Exception:
            pass
        sys.exit(1)

    logger.info("Application closed normally")


if __name__ == "__main__":
    main()
