FROM anchore/engine-cli:v0.9.1

USER root

# Install diffutils for the demo
RUN yum install -y diffutils

COPY anchore-bundle /usr/local/bin/
COPY bundle.py /usr/local/bin/
COPY sample_input /anchore-cli/
COPY requirements.txt /anchore-cli/

RUN echo 'alias python=python3' >> ~anchore/.bashrc

RUN /usr/bin/python3.8 -m pip install -r /anchore-cli/requirements.txt && \
    rm /anchore-cli/requirements.txt && \
    chown -R anchore:anchore /anchore-cli/

USER anchore:anchore

#ENTRYPOINT ["/docker-entrypoint.sh"]
#CMD ["/bin/bash"]
