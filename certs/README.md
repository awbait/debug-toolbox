# certs/

Drop corporate root/intermediate CAs here (`*.crt` or `*.pem`, PEM-encoded) and
rebuild: they are added to the system trust store at build time
(`update-ca-certificates`). Everything else in this directory is ignored.

For CAs that should not be baked into the image, mount them at runtime into
`/etc/debug-toolbox/ca.d` instead - see "Custom CA certificates" in the top-level
README.
