import logging
import os
from datetime import datetime

LOG_FILE = f"{datetime.now().strftime('%m_%d_%Y_%H_%M_%S')}.log"

LOG_DIR = os.path.join(os.getcwd(), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logs_path = os.path.join(LOG_DIR, LOG_FILE)

logging.basicConfig(
    filename=logs_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)