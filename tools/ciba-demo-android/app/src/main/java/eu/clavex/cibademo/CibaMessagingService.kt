package eu.clavex.cibademo

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class CibaMessagingService : FirebaseMessagingService() {

    /**
     * Called when the FCM token is created or rotated.
     * Re-register with Clavex so push notifications reach this device.
     */
    override fun onNewToken(token: String) {
        CoroutineScope(Dispatchers.IO).launch {
            ClavexRepository.registerPushToken(token, "fcm")
        }
    }

    /**
     * Called for every incoming FCM message.
     *
     * Clavex sends a data-plus-notification message with:
     *   data["auth_req_id"], data["approve_url"], data["deny_url"], data["expires_in"]
     *   notification.title, notification.body (the binding_message)
     */
    override fun onMessageReceived(message: RemoteMessage) {
        val data        = message.data
        val authReqId   = data["auth_req_id"]  ?: return
        val approveUrl  = data["approve_url"]  ?: return
        val denyUrl     = data["deny_url"]     ?: return
        val expiresIn   = data["expires_in"]?.toIntOrNull() ?: 120
        val bindingMsg  = message.notification?.body
            ?: message.data["binding_message"]
            ?: "Authentication request"

        val req = CibaRequest(
            authReqId      = authReqId,
            approveUrl     = approveUrl,
            denyUrl        = denyUrl,
            expiresIn      = expiresIn,
            bindingMessage = bindingMsg,
        )

        // Update the global state — MainActivity observes this and shows the sheet.
        CibaPendingStore.update(req)
    }
}
