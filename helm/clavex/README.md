# Clavex Helm Chart

Self-hosted Identity & Access Management — OIDC, OAuth 2.0, SAML 2.0, SCIM 2.0,
FAPI 2.0, and the eIDAS 2.0 / EU Digital Identity Wallet stack.

```bash
helm install clavex ./helm/clavex -f my-values.yaml
```

See [`values.yaml`](values.yaml) for the full, commented configuration surface.

## Post-Quantum TLS Transport

Clavex negotiates the hybrid post-quantum key-exchange group **`X25519MLKEM768`**
(classical X25519 + ML-KEM-768, NIST FIPS 203) for TLS 1.3, pinned explicitly in
`internal/crypto/tls.BuildServerTLSConfig`. This is the transport-layer
counterpart to the ML-DSA-65 token-signature work; the two are independent. See
[`docs/PQC-ROADMAP.md`](../../docs/PQC-ROADMAP.md) for the full picture.

**The TLS termination point determines whether PQC transport is active
end-to-end.** When an ingress/reverse proxy terminates TLS in front of Clavex,
the client-facing hop uses the *proxy's* TLS stack — so the proxy, not just
Clavex, must support the hybrid group.

### Recommended for PQC-ready deployments (Traefik)

- **Traefik Proxy ≥ v3.5** — `X25519MLKEM768` support was introduced in Traefik
  Proxy v3.5; earlier 3.x releases do not offer the hybrid group. The requirement
  that matters is the **proxy** version, not the Helm chart version.

  Verify the Traefik Proxy version actually running, independent of the Helm
  chart number:

  ```bash
  kubectl exec -it <traefik-pod> -- traefik version
  # or inspect the installed chart's bundled proxy version:
  helm show chart traefik/traefik | grep appVersion
  ```

  > **Note:** the Traefik Helm chart version (`traefik/traefik-helm-chart`, or a
  > repackaged `bitnami/traefik`) changes far more frequently than the Traefik
  > Proxy it bundles. Do not trust a chart number written in static documentation —
  > always confirm `appVersion` or the output of `traefik version` before
  > deployment.
- **Allow TLS 1.3 in the ingress `TLSOption`.** `X25519MLKEM768` is a TLS
  1.3-only group. A `TLSOption` with `maxVersion: VersionTLS12` **disables**
  post-quantum key exchange at the edge, regardless of Clavex's own
  configuration. For PQC-ready end-to-end transport, ensure the `TLSOption`
  serving the Clavex route permits TLS 1.3.

Without both conditions, Clavex still runs correctly — clients simply fall back
to classical key exchange at the edge, with no post-quantum protection on the
client-facing hop.
