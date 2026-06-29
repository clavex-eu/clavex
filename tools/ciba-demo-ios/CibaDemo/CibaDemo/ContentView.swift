import SwiftUI
import AuthenticationServices

// MARK: - Root view

struct ContentView: View {
    @EnvironmentObject var auth: AuthState
    @EnvironmentObject var cibaStore: CibaPendingStore

    var body: some View {
        Group {
            if auth.isSignedIn {
                HomeView()
                    .sheet(item: $cibaStore.pending) { request in
                        CIBAApprovalView(request: request)
                    }
            } else {
                SignInView()
            }
        }
    }
}

// MARK: - Sign-in view (PKCE)

struct SignInView: View {
    @State private var isLoading = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 64))
                .foregroundColor(.accentColor)
            Text("Clavex CIBA Demo")
                .font(.largeTitle.bold())
            Text("PSD2 SCA push authentication test")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            if let err = errorMessage {
                Text(err).foregroundColor(.red).font(.caption)
            }
            Button {
                Task { await signIn() }
            } label: {
                HStack {
                    if isLoading { ProgressView().tint(.white) }
                    Text("Sign in with Clavex")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(isLoading)
            .padding(.horizontal, 32)
            Spacer()
        }
        .padding()
    }

    @MainActor
    private func signIn() async {
        isLoading = true
        defer { isLoading = false }

        // Build PKCE parameters
        let verifier = PKCEHelper.generateVerifier()
        guard let challenge = PKCEHelper.computeChallenge(from: verifier),
              let authURL = buildAuthURL(codeChallenge: challenge)
        else {
            errorMessage = "Could not build authorization URL"
            return
        }

        do {
            let callbackURL = try await withCheckedThrowingContinuation { cont in
                let session = ASWebAuthenticationSession(
                    url: authURL,
                    callbackURLScheme: "eu.clavex.cibademo"
                ) { url, error in
                    if let url { cont.resume(returning: url) }
                    else { cont.resume(throwing: error ?? URLError(.cancelled)) }
                }
                session.presentationContextProvider = PresentationAnchor()
                session.prefersEphemeralWebBrowserSession = false
                session.start()
            }

            // Extract code from callback
            guard let code = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?
                .queryItems?.first(where: { $0.name == "code" })?.value
            else { throw URLError(.badServerResponse) }

            // Exchange code for tokens
            let tokens = try await exchangeCode(code, verifier: verifier)
            AuthState.shared.store(accessToken: tokens.accessToken)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func buildAuthURL(codeChallenge: String) -> URL? {
        var comps = URLComponents(string: "\(Config.issuer)/authorize")
        comps?.queryItems = [
            .init(name: "response_type", value: "code"),
            .init(name: "client_id", value: Config.clientID),
            .init(name: "redirect_uri", value: Config.redirectURI),
            .init(name: "scope", value: "openid email profile"),
            .init(name: "code_challenge", value: codeChallenge),
            .init(name: "code_challenge_method", value: "S256"),
            .init(name: "state", value: UUID().uuidString),
        ]
        return comps?.url
    }

    private func exchangeCode(_ code: String, verifier: String) async throws -> (accessToken: String, idToken: String) {
        guard let url = URL(string: "\(Config.issuer)/token") else { throw URLError(.badURL) }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let body = [
            "grant_type=authorization_code",
            "client_id=\(Config.clientID)",
            "code=\(code)",
            "redirect_uri=\(Config.redirectURI)",
            "code_verifier=\(verifier)",
        ].joined(separator: "&")
        req.httpBody = body.data(using: .utf8)
        let (data, _) = try await URLSession.shared.data(for: req)
        guard
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            let at = json["access_token"] as? String,
            let it = json["id_token"] as? String
        else { throw URLError(.badServerResponse) }
        return (at, it)
    }
}

// MARK: - Home view

struct HomeView: View {
    @EnvironmentObject var auth: AuthState

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 56))
                    .foregroundColor(.green)
                Text("Signed in")
                    .font(.title2.bold())
                Text("Waiting for a CIBA push notification…\nAPNs device token is registered.")
                    .multilineTextAlignment(.center)
                    .foregroundColor(.secondary)
                    .font(.body)
            }
            .padding()
            .navigationTitle("Clavex CIBA Demo")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Sign out") { auth.signOut() }
                }
            }
        }
    }
}

// MARK: - CIBA approval sheet

struct CIBAApprovalView: View {
    let request: CIBARequest
    @EnvironmentObject var cibaStore: CibaPendingStore
    @State private var isLoading = false
    @State private var finished = false
    @State private var approved = false

    var body: some View {
        NavigationStack {
            if finished {
                VStack(spacing: 24) {
                    Image(systemName: approved ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .font(.system(size: 64))
                        .foregroundColor(approved ? .green : .red)
                    Text(approved ? "Payment Approved" : "Payment Denied")
                        .font(.title2.bold())
                    Text("You can close this screen.")
                        .foregroundColor(.secondary)
                    Button("Done") { cibaStore.pending = nil }
                        .buttonStyle(.borderedProminent)
                }
                .padding()
            } else {
                VStack(spacing: 24) {
                    Spacer()
                    Image(systemName: "eurosign.circle.fill")
                        .font(.system(size: 56))
                        .foregroundColor(.accentColor)
                    Text("Payment Request")
                        .font(.title2.bold())

                    // EBA SCA: binding_message must be prominently displayed
                    GroupBox {
                        Text(request.bindingMessage)
                            .font(.body)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: .infinity)
                    } label: {
                        Label("Confirm this transaction", systemImage: "lock.shield")
                    }
                    .padding(.horizontal)

                    Text("This request expires in \(request.expiresIn) seconds")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Spacer()

                    HStack(spacing: 16) {
                        Button("Deny", role: .destructive) {
                            Task { await decide(approve: false) }
                        }
                        .buttonStyle(.bordered)
                        .disabled(isLoading)

                        Button {
                            Task { await decide(approve: true) }
                        } label: {
                            HStack {
                                if isLoading { ProgressView().tint(.white) }
                                Text("Approve")
                            }
                            .frame(minWidth: 100)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isLoading)
                    }
                    .padding(.bottom, 32)
                }
                .navigationTitle("Authenticate")
                .navigationBarTitleDisplayMode(.inline)
            }
        }
    }

    private func decide(approve: Bool) async {
        isLoading = true
        let url = approve ? request.approveURL : request.denyURL
        let ok = await ClavexClient.shared.postDecision(to: url)
        await MainActor.run {
            isLoading = false
            self.approved = approve && ok
            self.finished = true
        }
    }
}

// MARK: - ASWebAuthenticationSession presentation

final class PresentationAnchor: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow } ?? ASPresentationAnchor()
    }
}

// MARK: - PKCE helpers

enum PKCEHelper {
    static func generateVerifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func computeChallenge(from verifier: String) -> String? {
        guard let data = verifier.data(using: .utf8) else { return nil }
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &digest) }
        return Data(digest).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
