import Foundation

// MARK: - Configuration
// Edit these values before running the demo.

enum Config {
    /// Your Clavex org issuer URL, e.g. "https://id.bank.eu/acme"
    static let issuer = "https://id.example.com/demo"

    /// Public OIDC SPA client_id registered in Clavex (authorization_code + PKCE)
    static let clientID = "ciba-demo-ios"

    /// Must match a redirect URI registered on the client.
    static let redirectURI = "eu.clavex.cibademo://callback"
}
