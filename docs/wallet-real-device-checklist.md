# Wallet fisico: checklist di interoperabilità

Aggiornamento 30 ottobre 2026. **Prova automatica sul telefono non eseguita**. Il laboratorio suite
non sostituisce il dispositivo e non dimostra il riconoscimento in un ecosistema
nazionale. Usare un tenant e dati sintetici, senza collegare utenti reali.

## Identificare il client

| Client indicato dall'autore | Informazioni note | Dato ancora necessario |
| --- | --- | --- |
| EUDI reference Android ricompilato | Checkout `045c1d56` del 4 giugno 2026; Core `0.28.1`; APK `demoDebug` del medesimo giorno, confermato dall’autore. Versione visualizzata `yyyy.mm.v`. CA Clavex aggiunta al solo reader trust store. | Richiesta reale del verifier e log di selezione dei documenti |
| HopaeEUDIWALLET iOS | Versione 1.0.1 | Profilo supportato e modalità di onboarding/trust documentate per questa app/versione |

Non trasferire automaticamente a Hopae le impostazioni della reference app EC.
Una prova con una build Android aggiornata deve avere un proprio verbale, distinto
da quello della build sopra identificata.

## Preset del verifier e segnalazione Android

Il verifier distingue esplicitamente i formati nei preset. I PID non sono
intercambiabili tra SD-JWT e mdoc:

| Preset | Formato | Tipo richiesto | Namespace dei claim |
| --- | --- | --- | --- |
| PID / età SD-JWT | `dc+sd-jwt` | `vct=urn:eudi:pid:1` | Claim alla radice |
| PID / età mdoc | `mso_mdoc` | `doctype=eu.europa.ec.eudi.pid.1` | `eu.europa.ec.eudi.pid.1` |
| mDL | `mso_mdoc` | `doctype=org.iso.18013.5.1.mDL` | `org.iso.18013.5.1` |

Il preset età SD-JWT usa ora il VCT del PID SD-JWT anziché l'identificatore del
PID mdoc. La richiesta età richiede soltanto `age_over_18` nel rispettivo formato;
non richiede un'attestazione autonoma di età con un tipo diverso.

L'autore segnala il messaggio «The requested document is not available in your
EUDI Wallet» sia per mDL sia per PID. Nel codice Android questo testo corrisponde
allo stato `NoData`: nessun elemento richiesto disponibile oppure nessun documento
rimasto dopo la trasformazione e il filtro dei documenti revocati. Non identifica
una causa unica. Confrontare la richiesta realmente distribuita con formato,
VCT/doctype, namespace, campi, disponibilità delle credenziali e stato dei documenti.
Il preset mDL era già mdoc: il suo fallimento non è spiegato dall'assenza del preset
PID mdoc. Le nuove scelte UI non dimostrano il superamento della prova sul telefono.

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
