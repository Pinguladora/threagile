# The threagile image: the static binary and typst, which renders the PDF report, on the minimal hi/static base.
# GoReleaser builds it (dockers_v2 in .goreleaser.yaml) with the binary of each platform at $TARGETPLATFORM/threagile
# in the build context. Both base images are pinned by the digest of their multi-platform index.

# The official typst image: its typst is a static (musl) binary, so it runs on hi/static as it is.
FROM ghcr.io/typst/typst:0.15.1@sha256:032e292249bcd378480cc7c142cfa324b63ef8aadeb88d7e7230320c4c9c422f AS typst

FROM registry.access.redhat.com/hi/static:latest@sha256:f4d5109b57cf7eab0a7adc566f2d78f80fa0c5ec9ccab698c9fb8eb448db6071
ARG TARGETPLATFORM
COPY --from=typst /bin/typst /usr/bin/typst
COPY $TARGETPLATFORM/threagile /usr/bin/threagile
USER 65532:65532
ENTRYPOINT ["/usr/bin/threagile"]
