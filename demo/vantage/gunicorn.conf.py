# Read by gunicorn from the working directory. The distroless image has no
# shell to expand $PORT on the command line, so the port is read here.
import os

bind = f":{os.environ.get('PORT', '8080')}"
workers = 1
threads = 8
timeout = 30
