# Verifica wallet — 29 ottobre 2026

Stato: implementazioni locali dei macro-punti 1–3 adattate nei repository privato
`/root/projects/clavex_private` e pubblico
`/root/projects/personal/clavex-eu/clavex`. Macro-punto 4 in corso, **non chiuso**.
Interventi organizzati in commit locali separati; nessun push o deployment. Nessuna attestazione di
conformità EUDI, IT-Wallet, eIDAS, EHDS o certificazione OpenID.

## Implementazioni e perimetro

| Area | Comportamento implementato | Riferimento |
| --- | --- | --- |
| Status/revoche | Liste JWT remote con signer/URI autorizzati per tenant, cache limitata e trasporto SSRF protetto; CRL complete/direct; rivalutazione IACA; sospensione distinta dalla revoca; monitoraggio e propagazione dello stato delle attestazioni parent | [Status remoto](../wallet-status-remote.md), migrazioni 188–189 |
| Deferred | Authorization-code con PKCE, scope/RAR, grant stabile, refresh a rotazione, deadline, vincoli DPoP/mTLS/istanza; client public, secret, private-key e attestati | [Authorization-code](../wallet-authorization-code.md), migrazioni 190–191 |
| DCQL/CIBA | Più query e istanze, formati misti, alternative/opzionalità, risultati separati, controlli di firma/trust/stato e collegamento account per ogni credenziale presentata | [DCQL](../wallet-dcql-multiple.md), [binding account](../wallet-account-binding.md) |

Il collegamento CIBA non deduce identità da email, nome o sola chiave holder.
Un account diverso o un mapping esterno assente/revocato impedisce l'approvazione.
Questi controlli non costituiscono un motore di autorizzazione clinica EHDS.

Durante il confronto con le specifiche e la suite sono state corrette anche
assunzioni troppo restrittive sui claim: `iss` non universalmente obbligatorio
nelle key attestation; `iss` e `exp` non entrambi obbligatori nel profilo JWT
Token Status List draft 21. Rimangono obbligatori signer autorizzato, riferimenti
esatti e freschezza limitata; i profili nazionali possono richiedere quei claim.
La key attestation senza issuer richiede un solo signer configurato non ambiguo.
Nessuna fiducia viene derivata da una chiave auto dichiarata nell'header.

Il nonce endpoint ora restituisce il solo `c_nonce` previsto dalla Final, con
scadenza ancora applicata dallo store. Le offerte non aggiungono il parametro
legacy `tx_code.required`. I token legacy mantengono le proprie risposte separate.
Il replay store indisponibile ora impedisce l'autenticazione con assertion,
anche nel validatore OIDC condiviso.

## Test locali

- `go test -race ./...`: superato nei due moduli, con PostgreSQL/Redis temporanei
  e database distinti creati per la suite completa; 49 package con test nel
  privato, 44 nel pubblico. I package senza test non sono contati come test.
- Le successive correzioni dei claim e del wire format hanno avuto test mirati
  con race detector in entrambi i repository; il laboratorio `_test.go` viene
  saltato nell'esecuzione ordinaria senza configurazione esplicita.
- `npm run build`: superato in entrambi i frontend, incluso TypeScript. Avviso
  sui bundle superiori a 500 kB, non errore di build.
- Migrazioni: applicazione fino a 191 su database vuoti nei due moduli;
  roundtrip 191→186→191 su un ulteriore database isolato. Guardie 188–191
  provate con dati sintetici: rifiutano il rollback che eliminerebbe nuovo stato
  o vincoli; nessuna fixture della prova è rimasta nel database.
- Playwright/Chromium: login reale, storico della sessione verificata e claim
  sintetici nella UI. Trovato e corretto il taglio del verifier su mobile:
  navigazione compatta accessibile nel layout tenant e pannelli in colonna.
  Verificati 320, 390, 768, 1024 e 1440 px, con larghezza effettiva dell'area
  principale, visibilità sidebar e assenza di overflow anche nel contenitore.
  Navigazione mobile fra Credential Status e Wallet Verifier e focus del
  selettore verificati; nessun errore JavaScript. Build ripetute nei due frontend.
  Questa prova UI riguarda il caso singolo; i risultati multipli sono coperti
  dai test locali di protocollo/CIBA, non da una prova completa su telefono.

Log di questa sessione in `/tmp/clavex-wallet-final-{private,public}-tests.log`,
`/tmp/clavex-wallet-final-{private,public}-frontend.log`,
`/tmp/clavex-wallet-public-final-delta.log`,
`/tmp/clavex-wallet-final-wire-{private,public}.log`,
`/tmp/clavex-wallet-migration-{roundtrip,guards}.log`,
`/tmp/clavex-wallet-responsive-{private,public}-build.log` e
`/tmp/clavex-wallet-ui-responsive-matrix.log`.
Gli artefatti temporanei non sostituiscono una pipeline CI riproducibile.
Il laboratorio è stato arrestato dopo l’esportazione delle evidenze; backup
Mongo della suite e fixture SQL sintetica restano in
`/tmp/clavex-wallet-conformance-20261029/`, con permessi 0600. Nessun servizio
del laboratorio è lasciato esposto per eseguire prove con il telefono.

## Suite OpenID esterna

Suite ufficiale compilata da sorgenti **senza modifiche**, commit
`23353b36957d6466010de767c812d2c91ed37638`, repository
[openid/conformance-suite](https://gitlab.com/openid/conformance-suite).
Eseguita localmente con dati sintetici sul codice del repository privato;
il porting pubblico ha verifiche Go/build indipendenti, non un secondo run esterno.
Piani e varianti selezionati, non l'intera matrice di certificazione.

| Prove | Esito ufficiale |
| --- | --- |
| Metadati issuer OID4VCI, normali e firmati | 2 PASSED |
| OID4VCI: nonce errato, firma proof errata, firma key attestation errata, proof assente, configurazione sconosciuta, identificatore sconosciuto | 6 PASSED |
| OID4VP: firme credenziale/holder errate, sd_hash errato, nonce/audience errati, iat passato/futuro, credenziale revocata, VCT errato | 9 PASSED |
| OID4VP presentazione valida | FINISHED / REVIEW: Clavex ha verificato la credenziale; screenshot della UI reale allegato alla suite, revisione umana ancora necessaria |
| OID4VCI emissione valida e modulo access-token-in-query | 2 FAILED: entrambi fermati sulla risoluzione della chiave della status list |

[Evidenza sanitizzata con ID ed esiti](wallet-conformance-2026-10-29.json).
Totale: **17 PASSED, 1 REVIEW, 2 FAILED**, senza reinterpretare gli stati.
Le prime esecuzioni interrotte per laboratorio non ancora pronto o invio prima
dello stato WAITING sono conservate nei file temporanei e non conteggiate come
prove di comportamento del prodotto. Non sono state cancellate dalla suite.

L'errore comune ai due FAILED è
`VerifyStatusListTokenSignatureUsingEmbeddedJwk`: nessuna chiave embedded e nessun
`server_jwks` disponibile nella suite. Nel percorso OAuth pre-autorizzato scelto,
il modulo comune carica le chiavi server solo con OpenID o JARM; Clavex firma la
lista con `kid` e pubblica le chiavi nella JWKS dell'authorization server.
La lettura del sorgente individua un limite di risoluzione in questa combinazione,
**non dimostra da sola la conformità dell'emissione o della lista**. Non sono stati
aggiunti header JWK auto dichiarati, tolti status o modificata la suite per
ottenere un pass. Nel modulo access-token-in-query manca la prova esterna della
specifica asserzione successiva al punto di arresto.

Il trasporto di produzione vieta loopback e indirizzi privati. Il laboratorio
usa `internal/server/wallet_conformance_lab_test.go`, escluso dai binari di
produzione: server vincolato a 127.0.0.1, CA temporanea ed eccezione verso la sola
porta HTTPS esplicita della suite. L'orchestrazione registra URI di lista esatti
solo dopo verifica della credenziale con issuer già autorizzato. Non è una nuova
opzione HTTP/tenant per disattivare i controlli SSRF o accettare chiavi arbitrarie.

Nel solo privato è stato corretto `conformance/run-tests.py`: rimappava WAITING e
INTERRUPTED di determinati moduli screenshot in PASSED. Ora conserva l'esito
originale. I vecchi riepiloghi non sono stati rigenerati come prova del nuovo
codice e richiedono lettura dei risultati originali. Il runner non è presente nel
pubblico e non è stato copiato come componente estraneo.

## Telefoni e fiducia: prova ancora da eseguire

Informazioni fornite dall'autore:

- Android: vecchia app EUDI reference ricompilata; versione/commit ignoti.
- iOS: HopaeEUDIWALLET **1.0.1**. Non viene equiparata alla reference app EC.

Nessuno dei due telefoni è stato comandato o provato da questo laboratorio.
Il rifiuto del certificato va localizzato tra TLS, firma della richiesta verifier,
catena issuer/document signer, trust anchor e registrazione del ruolo nel relativo
framework. Una CA inserita ricompilando l'app dimostra soltanto un trust di test.
Le versioni dei protocolli compatibili con queste due app restano da verificare.
Procedura: [checklist per il dispositivo reale](../wallet-real-device-checklist.md).

## Limiti e ordine delle verifiche rimanenti

1. Risolvere/documentare il reperimento della chiave status nel piano OAuth
   ufficiale senza aggiramenti; rieseguire i due casi e completare la matrice
   esterna, inclusi authorization-code/deferred, metodi confidenziali e DCQL multiplo.
2. Eseguire la prova sui wallet fisici con versione/profilo e radici di test
   identificati. La versione sorgente Android serve a riprodurre quel client;
   per iOS servono modalità di onboarding supportate da Hopae 1.0.1, non istruzioni
   dedotte da una diversa app.
3. Se richiesti dal profilo target, implementare separatamente status CWT e
   identifier lists per mdoc, OCSP/delta CRL, trust-list/onboarding e certificati
   di registrazione del framework. L'estensione MSO JWT implementata non copre
   universalmente ISO mdoc/HAIP. Il trust client-attestation registrato non è
   ancora il modello completo di fiducia dei wallet provider EUDI.
4. `trusted_authorities` DCQL viene rifiutato esplicitamente; un DeviceResponse
   mdoc contiene un documento per istanza. Nessun claim di interoperabilità
   universale deriva dai test delle altre combinazioni.

RLS, irrobustimento AuthZEN e requisiti clinici EHDS restano fuori da questo
incremento e successivi alla stabilizzazione concordata. Il checkout privato
storico non è stato modificato. Dati cliente, pagamenti, regole di licenza del
software e proprietà intellettuale non sono stati modificati da questi lavori.

Riferimenti tecnici: [OID4VCI Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html),
[OID4VP Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html),
[Token Status List draft 21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html),
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html).
