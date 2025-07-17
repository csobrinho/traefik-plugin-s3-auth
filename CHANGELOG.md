# Changelog

## v0.0.20
First version, definitely not ready for production usage! Usage is simple.

### Add the plugin to traefik
```yaml
--experimental.plugins.s3auth.moduleName=github.com/csobrinho/traefik-plugin-s3-auth
--experimental.plugins.s3auth.version=v0.0.20 # Or the latest version.
```

### Create a traefik middleware
```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: s3-auth
  namespace: traefik
spec:
  plugin:
    s3auth:
      headerName: Authorization      # Default
      statusCode: 403                # Default
      credentials:
        - accessKeyId: urn:k8s:secret:s3-auth-secret:accessKeyId1
          accessSecretKey: urn:k8s:secret:s3-auth-secret:accessSecretKey1
          region: us-east-1
          service: s3
        - accessKeyId: urn:k8s:secret:s3-auth-secret:accessKeyId2
          accessSecretKey: urn:k8s:secret:s3-auth-secret:accessSecretKey2
          region: us-west-1
          service: s3
        ...
```

## Add the middleware to the IngressRoute
```yaml
kind: IngressRoute
apiVersion: traefik.io/v1alpha1
metadata:
  name: s3-ingress
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`s3.example.com`)
      kind: Rule
      middlewares:
        - name: s3-auth
          namespace: traefik
      services:
        - name: s3-service
          port: 80
```
