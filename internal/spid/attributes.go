package spid

import "github.com/crewjam/saml"

// AttributeDef describes a SPID attribute with its official name and friendly name.
type AttributeDef struct {
	FriendlyName string
}

// knownAttributes is the complete set of attributes defined by the SPID technical rules.
// Reference: SPID regola tecnica, allegato A.
var knownAttributes = map[string]AttributeDef{
	"spidCode":              {FriendlyName: "Codice Identificativo SPID"},
	"name":                  {FriendlyName: "Nome"},
	"familyName":            {FriendlyName: "Cognome"},
	"placeOfBirth":          {FriendlyName: "Luogo di nascita"},
	"countyOfBirth":         {FriendlyName: "Provincia di nascita"},
	"dateOfBirth":           {FriendlyName: "Data di nascita"},
	"gender":                {FriendlyName: "Sesso"},
	"companyName":           {FriendlyName: "Ragione sociale"},
	"registeredOffice":      {FriendlyName: "Sede legale"},
	"fiscalNumber":          {FriendlyName: "Codice fiscale"},
	"ivaCode":               {FriendlyName: "Partita IVA"},
	"idCard":                {FriendlyName: "Documento di identità"},
	"mobilePhone":           {FriendlyName: "Numero di telefono mobile"},
	"email":                 {FriendlyName: "Indirizzo e-mail"},
	"domicileStreetAddress": {FriendlyName: "Indirizzo domicilio"},
	"domicilePostalCode":    {FriendlyName: "CAP domicilio"},
	"domicileMunicipality":  {FriendlyName: "Comune domicilio"},
	"domicileProvince":      {FriendlyName: "Provincia domicilio"},
	"domicileNation":        {FriendlyName: "Nazione domicilio"},
	"address":               {FriendlyName: "Indirizzo"},
	"digitalAddress":        {FriendlyName: "Domicilio digitale"},
	"expirationDate":        {FriendlyName: "Data di scadenza"},
}

// AttributeSet defines predefined request profiles.
var (
	// AttributeSetMinimo: codice fiscale only (minimum required for most services)
	AttributeSetMinimo = []string{"spidCode", "name", "familyName", "fiscalNumber"}

	// AttributeSetBase: above + contact details
	AttributeSetBase = []string{
		"spidCode", "name", "familyName", "fiscalNumber",
		"email", "mobilePhone",
	}

	// AttributeSetFull: all personal + domicile attributes
	AttributeSetFull = []string{
		"spidCode", "name", "familyName", "placeOfBirth", "countyOfBirth",
		"dateOfBirth", "gender", "fiscalNumber",
		"email", "mobilePhone", "address", "digitalAddress",
	}
)

// SPIDIdentity holds the verified attributes extracted from a SPID assertion.
type SPIDIdentity struct {
	SpidCode     string `json:"spid_code"`
	FiscalNumber string `json:"fiscal_number"`
	Name         string `json:"name"`
	FamilyName   string `json:"family_name"`
	DateOfBirth  string `json:"date_of_birth,omitempty"`
	PlaceOfBirth string `json:"place_of_birth,omitempty"`
	Email        string `json:"email,omitempty"`
	MobilePhone  string `json:"mobile_phone,omitempty"`
	Level        int    `json:"level"` // 1, 2, or 3
}

// extractSPIDAttributes maps a SAML assertion's attribute statements to a SPIDIdentity.
func extractSPIDAttributes(a *saml.Assertion) *SPIDIdentity {
	id := &SPIDIdentity{}
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			val := ""
			if len(attr.Values) > 0 {
				val = attr.Values[0].Value
			}
			switch attr.Name {
			case "spidCode":
				id.SpidCode = val
			case "fiscalNumber":
				// SPID fiscal number is prefixed with "TINIT-"
				id.FiscalNumber = val
			case "name":
				id.Name = val
			case "familyName":
				id.FamilyName = val
			case "dateOfBirth":
				id.DateOfBirth = val
			case "placeOfBirth":
				id.PlaceOfBirth = val
			case "email":
				id.Email = val
			case "mobilePhone":
				id.MobilePhone = val
			}
		}
	}

	// Derive authn level from the AuthnContext in the assertion
	if a.AuthnStatements != nil {
		for _, stmt := range a.AuthnStatements {
			if stmt.AuthnContext.AuthnContextClassRef != nil {
				switch stmt.AuthnContext.AuthnContextClassRef.Value {
				case SpidL1:
					id.Level = 1
				case SpidL2:
					id.Level = 2
				case SpidL3:
					id.Level = 3
				}
			}
		}
	}
	if id.Level == 0 {
		id.Level = 2 // safe default
	}

	return id
}
