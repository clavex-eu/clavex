# Wallet fisico: checklist di interoperabilità

Checkpoint 29 ottobre 2026. **Prova non ancora eseguita**. Il laboratorio suite
non sostituisce il dispositivo e non dimostra il riconoscimento in un ecosistema
nazionale. Usare un tenant e dati sintetici, senza collegare utenti reali.

## Identificare il client

| Client indicato dall'autore | Informazioni note | Dato ancora necessario |
| --- | --- | --- |
| EUDI reference Android ricompilato | Build vecchia, versione non visibile | Repository, commit/tag e modifiche alla configurazione di trust |
| HopaeEUDIWALLET iOS | Versione 1.0.1 | Profilo supportato e modalità di onboarding/trust documentate per questa app/versione |

Non trasferire automaticamente a Hopae le impostazioni della reference app EC.
Se il sorgente Android non è recuperabile, un'eventuale prova con una build nuova
deve avere un proprio verbale: non sarebbe la riproduzione della vecchia build.

## Preparare un profilo dichiarato

Registrare prima: issuer URL e tenant, formato SD-JWT/mdoc, versioni OID4VCI/VP,
grant e metodo di autenticazione, trasporto della richiesta/risposta, tipo di
client identifier, algoritmo e catene issuer/verifier, formato status list,
radici/autorizzazioni ammesse dall'app. Verificare la compatibilità documentata
prima di proporre modifiche al prodotto o alla configurazione del telefono.

Separare le verifiche di fiducia:

1. **TLS:** il telefono raggiunge discovery, offerte, nonce, token, credential e
   status endpoint attraverso certificati e DNS validi, con catena completa.
2. **Issuer/document signer:** l'app riconosce la radice e il ruolo autorizzato a
   emettere il tipo di credenziale richiesto.
3. **Verifier/reader:** richiesta firmata, client identifier e certificato del
   verificatore soddisfano il profilo previsto dall'app.
4. **Attestazioni/status:** chiavi e riferimenti sono autorizzati da una policy
   esplicita. Un HTTP 200 o una firma valida non dimostrano la fiducia di framework.

Installare una CA di test soltanto se esiste una modalità di collaudo prevista
per quella specifica app. Annotare l'operazione. Non disattivare TLS, non accettare
chiavi JWT auto dichiarate e non ricompilare il wallet per mascherare il problema
come interoperabilità con l'app distribuita.

## Eseguire e raccogliere evidenza

1. Salvare versione/build e profilo; verificare discovery e metadati dal telefono.
2. Creare un'offerta nel tenant di test, consegnarla via QR/deep link e annotare
   il primo endpoint/controllo che fallisce, con orario e codice errore.
3. Provare l'emissione immediata, poi deferred con attesa oltre cinque minuti e
   rinnovo. Registrare metodo client effettivo, binding e consegna unica; non
   presumere che un'app vecchia implementi il rinnovo richiesto.
4. Presentare una credenziale valida; confrontare ID sessione e risultato reale
   nel verifier. Ripetere con due credenziali se la versione supporta DCQL multiplo.
5. Sospendere la credenziale dal tenant di test, attendere la finestra di cache
   configurata e verificare il rifiuto. Ripristinare la sospensione e riprovare;
   revocare infine e verificare che il ripristino venga negato.
6. Per CIBA verificare separatamente account corretto, account differente e
   mapping mancante. Nessuna associazione automatica tramite email/nome.

Per ogni caso conservare esito atteso/reale, ID correlazione, fase, certificati
**pubblici** e relativi fingerprint. Non includere token, QR riutilizzabili,
credenziali integrali, password o chiavi private in screenshot/issue pubbliche.
Un errore di fiducia prima dello scambio protocollare non si risolve togliendo
controlli di revoca o allentando il collegamento account.

Il verbale deve distinguere PASSED, FAILED, incompatibilità di profilo e prova
non eseguita. Conformance suite, prova fisica e onboarding ufficiale sono tre
evidenze diverse. Stato corrente: [rapporto](reviews/WALLET_VERIFICATION_2026-10-29.md).
