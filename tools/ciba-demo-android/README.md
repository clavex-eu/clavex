# Clavex CIBA Demo — Android

Minimal Jetpack Compose app demonstrating **CIBA push** for PSD2 SCA with Clavex.

## What this does

1. Signs in via PKCE (Chrome Custom Tab)
2. Registers the FCM device token with Clavex at startup and on token rotation
3. Receives a CIBA data message from FCM containing the `binding_message`
4. Shows a bottom sheet — customer sees the payment details before deciding
5. POSTs Approve or Deny — the merchant's polling `/token` resolves immediately

## Setup

1. Edit `Config.kt`:
   ```kotlin
   const val ISSUER       = "https://id.your-bank.eu/your-org"
   const val CLIENT_ID    = "your-spa-client-id"
   const val REDIRECT_URI = "eu.clavex.cibademo://callback"
   ```

2. Register the redirect URI in Clavex:
   ```
   POST /api/v1/organizations/{org_id}/clients
   { "redirect_uris": ["eu.clavex.cibademo://callback"], ... }
   ```

3. Configure FCM credentials in Clavex:
   ```
   PUT /api/v1/organizations/{org_id}/settings/fcm
   { "service_account_json": "{ ... }" }
   ```

4. Add your `google-services.json` (from Firebase console) to `app/`.

5. Open in Android Studio Koala or newer. Build and run on a device or emulator.

## Testing without a real push

Use the Clavex admin console to manually trigger the approval flow:

```bash
# List pending CIBA requests
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://id.bank.eu/api/v1/organizations/$ORG_ID/ciba/pending

# Approve manually (simulates what the mobile app would POST)
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://id.bank.eu/api/v1/organizations/$ORG_ID/ciba/$AUTH_REQ_ID/approve
```

## Requirements

- Android Studio Koala+ (for Kotlin 2.x + Compose BOM 2024)
- Min SDK 26 (Android 8.0)
- A Firebase project with Cloud Messaging enabled
- A Clavex tenant with FCM credentials configured
