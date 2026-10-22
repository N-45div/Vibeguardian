# The live drill service. deploy.sh stages the repository's vibeguardian package next to
# this folder's files and builds this Dockerfile from that staging directory, so the image
# runs the same drill and probe code as the CI prover.
FROM cgr.dev/chainguard/python:latest-dev AS build
USER root
WORKDIR /src
COPY pyproject.toml README.md ./
COPY vibeguardian ./vibeguardian
COPY requirements.txt ./
RUN pip install --no-cache-dir --target /deps . -r requirements.txt

FROM cgr.dev/chainguard/python:latest
WORKDIR /app
COPY --from=build /deps /deps
COPY main.py gunicorn.conf.py ./
COPY static ./static
ENV PYTHONPATH=/deps PYTHONUNBUFFERED=1
CMD ["-m", "gunicorn", "main:app"]
