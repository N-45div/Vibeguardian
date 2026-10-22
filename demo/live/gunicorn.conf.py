# Read by gunicorn from the working directory (the image has no shell to expand $PORT).
# One worker: the running drill lives in this process, so every request must reach it.
import os

bind = f":{os.environ.get('PORT', '8080')}"
workers = 1
threads = 16
timeout = 60
