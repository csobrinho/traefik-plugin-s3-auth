# traefik-plugin-s3-auth
Traefik middleware plugin that validates the S3 `Authorization` header. If the header is valid then it will return a `200`. If it is invalid then a `401` will be returned.

A list containing access key ids and secret keys must be provided via config.
