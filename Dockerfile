FROM mirror.gcr.io/python:alpine as python

FROM mirror.gcr.io/mgoltzsche/podman as podman
RUN printf '%s\n' > /etc/containers/registries.conf \
    [registries.search] \
    registries=[\'docker.io\']
COPY --from=python / /
RUN mkdir -p /podman/module
COPY scan.py /podman
COPY module/ /podman/module

FROM scratch
COPY --from=podman / /
LABEL org.opencontainers.image.authors="mchinenov@swordfishsecurity.ru"
WORKDIR /podman
ENTRYPOINT ["python3", "scan.py"]
