package eu.clavex.cibademo

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

object ClavexRepository {
    private val http = OkHttpClient()

    /** Register (or re-register) a push device token with Clavex. */
    suspend fun registerPushToken(token: String, platform: String = "fcm") {
        val at = AuthState.accessToken ?: return
        val body = JSONObject().apply {
            put("platform", platform)
            put("device_token", token)
        }.toString().toRequestBody("application/json".toMediaType())

        val req = Request.Builder()
            .url("${Config.ISSUER}/push/device-token")
            .addHeader("Authorization", "Bearer $at")
            .post(body)
            .build()

        withContext(Dispatchers.IO) {
            runCatching { http.newCall(req).execute().close() }
        }
    }

    /** POST to an approve or deny URL. Returns true on HTTP 200. */
    suspend fun postDecision(url: String): Boolean {
        val at = AuthState.accessToken ?: return false
        val req = Request.Builder()
            .url(url)
            .addHeader("Authorization", "Bearer $at")
            .post("".toRequestBody())
            .build()
        return withContext(Dispatchers.IO) {
            runCatching { http.newCall(req).execute().use { it.isSuccessful } }.getOrDefault(false)
        }
    }

    /** Exchange an authorization code for tokens (PKCE). */
    suspend fun exchangeCode(code: String, codeVerifier: String): String? {
        val body = listOf(
            "grant_type=authorization_code",
            "client_id=${Config.CLIENT_ID}",
            "code=$code",
            "redirect_uri=${Config.REDIRECT_URI}",
            "code_verifier=$codeVerifier",
        ).joinToString("&").toRequestBody("application/x-www-form-urlencoded".toMediaType())

        val req = Request.Builder()
            .url("${Config.ISSUER}/token")
            .post(body)
            .build()

        return withContext(Dispatchers.IO) {
            runCatching {
                http.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) return@use null
                    val json = JSONObject(resp.body?.string() ?: return@use null)
                    json.optString("access_token").takeIf { it.isNotBlank() }
                }
            }.getOrNull()
        }
    }
}
