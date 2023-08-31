FROM python:3.11

# Set user UID and GID as build arguments (default to 1000)
ARG UID=1000
ARG GID=1000

# Add a user with the specified UID and GID
RUN     groupadd -g $GID app \
    &&  useradd -u $UID -g $GID -s /bin/bash -m app

# Set the working directory and permissions for the user
WORKDIR /app
RUN chown app:app /app

# Install pipenv
RUN pip install --no-cache-dir pipenv

# Install dependencies
COPY Pipfile* ./
ARG PIPENV_INSTALL_ARG="--deploy"
RUN PIPENV_VENV_IN_PROJECT=1 pipenv install --system ${PIPENV_INSTALL_ARG}

COPY . .

USER app
CMD ["python", "-m", "src.main"]
