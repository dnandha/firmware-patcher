FROM python:3.12-slim

WORKDIR /app
RUN chown nobody:nogroup /app

ADD requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=nobody:nogroup . ./
USER nobody

STOPSIGNAL SIGINT
ENTRYPOINT [ "flask", "run", "-h", "0.0.0.0" ]