# Image for the real-kernel integration tests. Run it privileged (make
# integration): the tests mount filesystems and set ACLs and attributes.
FROM golang:1.27
RUN apt-get update \
 && apt-get install -y --no-install-recommends acl attr e2fsprogs util-linux \
 && rm -rf /var/lib/apt/lists/*
