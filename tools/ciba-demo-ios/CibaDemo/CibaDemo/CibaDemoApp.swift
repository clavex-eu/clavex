// CibaDemo — Minimal SwiftUI test app for Clavex CIBA push
//
// Demonstrates the full PSD2 SCA loop:
//   1. Sign in via PKCE (ASWebAuthenticationSession)
//   2. Register APNs device token with Clavex
//   3. Receive CIBA push notification (content-available)
//   4. Show binding_message alert with Approve / Deny
//   5. POST decision to Clavex — merchant receives the token
//
// Configuration: edit Config.swift before running.
// Requires: iOS 17+, Xcode 16+, a real device for APNs sandbox.

import SwiftUI
import AuthenticationServices
import UserNotifications

@main
struct CibaDemoApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(AuthState.shared)
                .environmentObject(CibaPendingStore.shared)
        }
    }
}
