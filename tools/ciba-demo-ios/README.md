# Clavex CIBA Demo — iOS

Minimal SwiftUI app demonstrating **CIBA push** for PSD2 SCA with Clavex.

## What this does

1. Signs in via PKCE (browser redirect)
2. Registers the APNs device token with Clavex at startup
3. Receives a CIBA push notification containing the `binding_message`
4. Shows an approval screen — the customer sees the exact payment details
5. POSTs Approve or Deny — the merchant's polling `/token` request resolves

## Setup

1. Edit `Config.swift`:
   ```swift
   Config.issuer    = "https://id.your-bank.eu/your-org"
   Config.clientID  = "your-spa-client-id"
   Config.redirectURI = "eu.clavex.cibademo://callback"
   ```

2. Register the redirect URI in Clavex:
   ```
   POST /api/v1/organizations/{org_id}/clients
   { "redirect_uris": ["eu.clavex.cibademo://callback"], ... }
   ```

3. Configure APNs credentials in Clavex:
   ```
   PUT /api/v1/organizations/{org_id}/settings/apns
   { "key_p8": "...", "key_id": "A1B2C3D4E5", "team_id": "TEAM123", "bundle_id": "eu.clavex.cibademo" }
   ```

4. Open `CibaDemo.xcodeproj` in Xcode 16+, set your Apple Developer team,
   build and run on a physical device (APNs requires a real device).

5. In your Xcode project, add the **Push Notifications** capability and
   enable **Background Modes → Remote notifications**.

## Testing without APNs

Use the Clavex admin console to manually approve pending CIBA requests:

```bash
# List pending requests
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://id.bank.eu/api/v1/organizations/$ORG_ID/ciba/pending

# Manually approve
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://id.bank.eu/api/v1/organizations/$ORG_ID/ciba/$AUTH_REQ_ID/approve
```

## Requirements

- Xcode 16+
- iOS 17+ deployment target
- Physical iOS device for APNs (simulator will compile but push won't work)
