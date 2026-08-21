import logging
import sys

def setup_logger(name: str = "phishshield") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    return logger

logger = setup_logger()
