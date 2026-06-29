import Foundation
import Combine

// MARK: - Auth state

@MainActor
final class AuthState: ObservableObject {
    static let shared = AuthState()
    @Published var accessToken: String?
    @Published var isSignedIn: Bool = false

    private init() {
        accessToken = UserDefaults.standard.string(forKey: "access_token")
        isSignedIn = accessToken != nil
    }

    func store(accessToken: String) {
        self.accessToken = accessToken
        self.isSignedIn = true
        UserDefaults.standard.set(accessToken, forKey: "access_token")
    }

    func signOut() {
        accessToken = nil
        isSignedIn = false
        UserDefaults.standard.removeObject(forKey: "access_token")
    }
}

// MARK: - Pending CIBA request

struct CIBARequest: Identifiable {
    let id = UUID()
    let authReqID: String
    let approveURL: String
    let denyURL: String
    let expiresIn: Int
    let bindingMessage: String
}

@MainActor
final class CibaPendingStore: ObservableObject {
    static let shared = CibaPendingStore()
    @Published var pending: CIBARequest?
    private init() {}
}

// MARK: - Clavex API client

actor ClavexClient {
    static let shared = ClavexClient()
    private var tokenID: String?
    private let session = URLSession.shared

    /// Register the APNs device token with Clavex.
    func registerPushToken(_ deviceToken: String, platform: String = "apns") async {
        guard let at = await AuthState.shared.accessToken,
              let url = URL(string: "\(Config.issuer)/push/device-token")
        else { return }

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(at)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: [
            "platform": platform,
            "device_token": deviceToken
        ])

        do {
            let (data, resp) = try await session.data(for: req)
            if let http = resp as? HTTPURLResponse, http.statusCode == 201 {
                let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
                tokenID = json?["id"] as? String
            }
        } catch { /* log */ }
    }

    /// Post an approve or deny decision.
    @discardableResult
    func postDecision(to urlString: String) async -> Bool {
        guard let at = await AuthState.shared.accessToken,
              let url = URL(string: urlString)
        else { return false }

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(at)", forHTTPHeaderField: "Authorization")

        do {
            let (_, resp) = try await session.data(for: req)
            return (resp as? HTTPURLResponse)?.statusCode == 200
        } catch { return false }
    }
}
