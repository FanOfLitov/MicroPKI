import logging
import sys
from datetime import datetime


class MicroPKILogger:
    """Custom logger for MicroPKI with timestamp and level formatting."""
    
    def __init__(self, logger):
        self.logger = logger
    
    def _log(self, level, message, *args):
        """Internal logging method with ISO 8601 timestamp."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        formatted_message = message % args if args else message
        log_entry = f"[{timestamp}] {level}: {formatted_message}"
        
        if level == "INFO":
            self.logger.info(log_entry)
        elif level == "WARNING":
            self.logger.warning(log_entry)
        elif level == "ERROR":
            self.logger.error(log_entry)
    
    def info(self, message, *args):
        """Log info message."""
        self._log("INFO", message, *args)
    
    def warning(self, message, *args):
        """Log warning message."""
        self._log("WARNING", message, *args)
    
    def error(self, message, *args):
        """Log error message."""
        self._log("ERROR", message, *args)


def setup_logger(log_file=None):
    """
    Setup and configure logger.
    
    Args:
        log_file: Path to log file. If None, logs to stderr.
    
    Returns:
        MicroPKILogger instance
    """
    logger = logging.getLogger('micropki')
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Create handler
    if log_file:
        handler = logging.FileHandler(log_file, mode='a')
    else:
        handler = logging.StreamHandler(sys.stderr)
    
    # Simple format (timestamp added by MicroPKILogger)
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return MicroPKILogger(logger)
