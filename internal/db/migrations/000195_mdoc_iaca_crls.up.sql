-- Public, signed CRLs only. Private CA keys are never stored here.
CREATE TABLE identity.mdoc_iaca_crls (
    org_id uuid NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    fingerprint text NOT NULL CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
    iaca_pem text NOT NULL,
    der bytea NOT NULL CHECK(octet_length(der) BETWEEN 1 AND 1048576),
    number bigint NOT NULL CHECK(number>=0),
    PRIMARY KEY(org_id,fingerprint)
);
