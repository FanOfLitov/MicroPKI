import logging
import os
import sys


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


class _MillisecondFormatter(logging.Formatter):

    default_msec_format = "%s.%03d"


def setup_logging(log_file: str | None = None, level: int = logging.INFO) -> logging.Logger:

    logger = logging.getLogger("micropki")
    logger.setLevel(level)
    logger.handlers.clear()

    formatter = _MillisecondFormatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger