package eu.clavex.cibademo

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

class MainActivity : ComponentActivity() {
    private val prefs by lazy { getSharedPreferences("ciba_demo", MODE_PRIVATE) }

    // PKCE: stored between OIDC redirect and callback
    private var pkceVerifier: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AuthState.restore(prefs)
        AppLifecycle.isForegrounded = true

        // Handle re-launch from the PKCE redirect URI
        handleOAuthCallback(intent)

        setContent {
            MaterialTheme {
                val pending by remember { derivedStateOf { CibaPendingStore.pending } }
                CibaDemoRoot(
                    onSignIn = { launchPKCE() },
                    onSignOut = { AuthState.signOut(prefs) },
                )
                pending?.let { req ->
                    CibaApprovalSheet(
                        request = req,
                        onDismiss = { CibaPendingStore.update(null) },
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleOAuthCallback(intent)
    }

    override fun onDestroy() {
        super.onDestroy()
        AppLifecycle.isForegrounded = false
    }

    private fun launchPKCE() {
        val verifier = generateVerifier().also { pkceVerifier = it }
        val challenge = computeChallenge(verifier)
        val authUri = Uri.parse("${Config.ISSUER}/authorize").buildUpon()
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("client_id", Config.CLIENT_ID)
            .appendQueryParameter("redirect_uri", Config.REDIRECT_URI)
            .appendQueryParameter("scope", "openid email profile")
            .appendQueryParameter("code_challenge", challenge)
            .appendQueryParameter("code_challenge_method", "S256")
            .appendQueryParameter("state", generateVerifier().take(16))
            .build()

        CustomTabsIntent.Builder().build().launchUrl(this, authUri)
    }

    private fun handleOAuthCallback(intent: Intent?) {
        val uri = intent?.data ?: return
        if (!uri.toString().startsWith(Config.REDIRECT_URI)) return
        val code = uri.getQueryParameter("code") ?: return
        val verifier = pkceVerifier ?: return
        pkceVerifier = null

        // Exchange code on background thread
        val scope = kotlinx.coroutines.MainScope()
        scope.launch {
            val token = ClavexRepository.exchangeCode(code, verifier)
            if (token != null) AuthState.store(token, prefs)
        }
    }

    // PKCE helpers
    private fun generateVerifier(): String {
        val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun computeChallenge(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray())
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}

// Root composable — signed-in or sign-in screen
@Composable
private fun CibaDemoRoot(onSignIn: () -> Unit, onSignOut: () -> Unit) {
    val isSignedIn by remember { derivedStateOf { AuthState.isSignedIn } }
    if (isSignedIn) {
        HomeScreen(onSignOut = onSignOut)
    } else {
        SignInScreen(onSignIn = onSignIn)
    }
}

@Composable
private fun SignInScreen(onSignIn: () -> Unit) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text("Clavex CIBA Demo", style = MaterialTheme.typography.headlineMedium,
                 fontWeight = FontWeight.Bold)
            Text("PSD2 SCA push authentication test",
                 style = MaterialTheme.typography.bodyMedium,
                 color = MaterialTheme.colorScheme.outline)
            Button(onClick = onSignIn) { Text("Sign in with Clavex") }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeScreen(onSignOut: () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Clavex CIBA Demo") },
                actions = {
                    TextButton(onClick = onSignOut) { Text("Sign out") }
                }
            )
        }
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text("Signed in ✓", style = MaterialTheme.typography.titleLarge,
                     fontWeight = FontWeight.Bold)
                Text("Waiting for a CIBA push notification…",
                     style = MaterialTheme.typography.bodyMedium,
                     color = MaterialTheme.colorScheme.outline)
            }
        }
    }
}
