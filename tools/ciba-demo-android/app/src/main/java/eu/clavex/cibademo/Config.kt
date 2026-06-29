package eu.clavex.cibademo

object Config {
    /** Your Clavex org issuer URL, e.g. "https://id.bank.eu/acme" */
    const val ISSUER = "https://id.example.com/demo"

    /** Public OIDC SPA client_id registered in Clavex (authorization_code + PKCE) */
    const val CLIENT_ID = "ciba-demo-android"

    /** Must match a redirect URI registered on the client. */
    const val REDIRECT_URI = "eu.clavex.cibademo://callback"
}
