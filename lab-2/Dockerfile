FROM python:3.12-slim-bookworm AS python-base

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_VERSION=1.8.3 \
    POETRY_HOME="/opt/poetry" \
    POETRY_CACHE_DIR="/.cache/pypoetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    PYSETUP_PATH="/opt/pysetup" \
    VENV_PATH="/opt/pysetup/.venv" \
    PATH="${POETRY_HOME}/bin:${VENV_PATH}/bin:${PATH}"

RUN apt-get update && apt-get install --no-install-recommends -y \
        curl \
        build-essential \
    && curl -sSL https://install.python-poetry.org | python3 -

WORKDIR ${PYSETUP_PATH}
COPY pyproject.toml poetry.lock ./

RUN --mount=type=cache,target=${POETRY_CACHE_DIR} \
    poetry install --no-root

WORKDIR /usr/src/app
COPY lab_2 ./lab_2
