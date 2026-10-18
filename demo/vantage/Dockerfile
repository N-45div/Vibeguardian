# Built from the repository root, so the image runs the same probe code as
# the prover:  docker build -f demo/vantage/Dockerfile .
#
# Chainguard's Python images are rebuilt continuously against fixed packages.
# The final stage has Python and the app only: no shell, no package manager,
# and it runs as a non-root user. Both stages track the same Python release.
FROM cgr.dev/chainguard/python:latest-dev AS build
USER root
WORKDIR /src
COPY pyproject.toml README.md ./
COPY vibeguardian ./vibeguardian
COPY demo/vantage/requirements.txt ./
RUN pip install --no-cache-dir --target /deps . -r requirements.txt

FROM cgr.dev/chainguard/python:latest
WORKDIR /app
COPY --from=build /deps /deps
COPY demo/vantage/main.py demo/vantage/gunicorn.conf.py ./
ENV PYTHONPATH=/deps PYTHONUNBUFFERED=1
CMD ["-m", "gunicorn", "main:app"]
