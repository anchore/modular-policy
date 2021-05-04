FROM anchore/engine-cli:v0.9.1

USER root

COPY anchore-bundle /usr/local/bin/
COPY bundle.py /usr/local/bin/

USER anchore:anchore
