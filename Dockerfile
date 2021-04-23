FROM anchore/engine-cli:v0.9.1

USER root

# Install diffutils git; define aliases for demo
RUN yum install -y diffutils git && echo -e "alias python=python3\nalias ll='ls -l'" >> ~anchore/.bashrc

COPY anchore-bundle /usr/local/bin/
COPY bundle.py /usr/local/bin/

WORKDIR /anchore-cli
RUN curl -so anchore_default_bundle.json https://raw.githubusercontent.com/anchore/anchore-engine/master/anchore_engine/conf/bundles/anchore_default_bundle.json
COPY *.csv /anchore-cli/
RUN chown -R anchore:anchore /anchore-cli/

USER anchore:anchore

RUN git config --global user.email "user@example.com" && git config --global user.name "User"

#ENTRYPOINT ["/docker-entrypoint.sh"]
#CMD ["/bin/bash"]
