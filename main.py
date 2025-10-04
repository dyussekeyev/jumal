import os
import sys
from ui.app import JUMALApp
from core.config import ConfigManager
from core.logging import init_logging

def ensure_dirs():
    for d in ("logs", "reports"):
        if not os.path.exists(d):
            os.makedirs(d, exist_ok=True)

def main():
    ensure_dirs()
    config_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "config.json")
    cfg_manager = ConfigManager(config_path)
    config = cfg_manager.load()
    logger = init_logging(config)
    logger.info("Starting JUMAL application")
    app = JUMALApp(cfg_manager, logger)
    app.run()

if __name__ == "__main__":
    main()