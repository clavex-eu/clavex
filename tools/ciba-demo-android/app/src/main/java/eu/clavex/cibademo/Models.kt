package eu.clavex.cibademo

import android.content.SharedPreferences
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

// MARK: - Auth state

object AuthState {
    var accessToken: String? by mutableStateOf(null)
        private set

    val isSignedIn get() = accessToken != null

    fun restore(prefs: SharedPreferences) {
        accessToken = prefs.getString("access_token", null)
    }

    fun store(token: String, prefs: SharedPreferences) {
        accessToken = token
        prefs.edit().putString("access_token", token).apply()
    }

    fun signOut(prefs: SharedPreferences) {
        accessToken = null
        prefs.edit().remove("access_token").apply()
    }
}

// MARK: - Pending CIBA request

data class CibaRequest(
    val authReqId: String,
    val approveUrl: String,
    val denyUrl: String,
    val expiresIn: Int,
    val bindingMessage: String,
)

object CibaPendingStore {
    var pending: CibaRequest? by mutableStateOf(null)
        private set

    fun update(req: CibaRequest?) {
        pending = req
    }
}

// MARK: - Simple foreground/background tracker

object AppLifecycle {
    var isForegrounded by mutableStateOf(false)
}
