FROM scratch
WORKDIR /
ADD testserver /
ADD docroot /docroot

ENTRYPOINT ["/testserver", "--document-root=/docroot", "--with-chromedp=ws://chrome:9222"]
