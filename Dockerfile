FROM gcr.io/distroless/cc-debian13

COPY --chmod=755 cnode /usr/local/bin/cnode

WORKDIR /etc/cnode
VOLUME ["/etc/cnode"]

ENTRYPOINT ["/usr/local/bin/cnode"]
CMD ["-c", "/etc/cnode/config.json"]
