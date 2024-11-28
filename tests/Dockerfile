FROM scratch
WORKDIR /
ADD testserver /
ADD docroot /docroot

ENTRYPOINT ["/testserver", "--document-root=/docroot"]
