FROM anchore/engine-cli:v0.9.1

USER root

# Install jq and diffutils for overriding allowlist
RUN yum install -y jq diffutils

USER anchore:anchore

#ENTRYPOINT ["/docker-entrypoint.sh"]
#CMD ["/bin/bash"]
