import UIKit
import UserNotifications

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        // Request push permission and register for remote notifications.
        UNUserNotificationCenter.current().delegate = self
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            guard granted else { return }
            DispatchQueue.main.async { UIApplication.shared.registerForRemoteNotifications() }
        }
        return true
    }

    // MARK: - APNs token registration

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        Task {
            await ClavexClient.shared.registerPushToken(token, platform: "apns")
        }
    }

    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error) {
        print("[CibaDemo] APNs registration failed: \(error)")
    }

    // MARK: - Background push (content-available: 1)

    func application(_ application: UIApplication,
                     didReceiveRemoteNotification userInfo: [AnyHashable: Any],
                     fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        guard
            let authReqID  = userInfo["auth_req_id"]  as? String,
            let approveURL = userInfo["approve_url"] as? String,
            let denyURL    = userInfo["deny_url"]    as? String
        else {
            completionHandler(.noData)
            return
        }
        let expiresIn  = (userInfo["expires_in"] as? Int) ?? 120
        // binding_message arrives in the alert body — fetch from notification center
        let bindingMsg = (userInfo["aps"] as? [String: Any])?["alert"] as? [String: Any]
        let body = bindingMsg?["body"] as? String ?? "Authentication request"

        Task { @MainActor in
            CibaPendingStore.shared.pending = CIBARequest(
                authReqID:      authReqID,
                approveURL:     approveURL,
                denyURL:        denyURL,
                expiresIn:      expiresIn,
                bindingMessage: body
            )
        }
        completionHandler(.newData)
    }

    // MARK: - Foreground notification display

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }
}
