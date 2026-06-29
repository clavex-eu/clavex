// Package geoip provides IP geolocation using a MaxMind GeoLite2 or GeoIP2
// mmdb database file.
//
// Usage:
//
//	db, err := geoip.Open("/path/to/GeoLite2-City.mmdb")
//	if err != nil { ... }
//	defer db.Close()
//
//	info := db.Lookup("203.0.113.42")
//	// info.CountryCode, info.City, info.ASNOrg
//
// If no database file is configured (empty path or Open fails), all Lookup
// calls return an empty GeoInfo without error — geo data is always optional.
package geoip

import (
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// GeoInfo contains the geographic metadata for a single IP address.
type GeoInfo struct {
	CountryCode string // ISO 3166-1 alpha-2, e.g. "IT"
	City        string
	ASNOrg      string // Autonomous System organisation name, e.g. "Telecom Italia"
}

// DB wraps an open MaxMind mmdb reader.
type DB struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader // optional: separate GeoLite2-ASN.mmdb
}

// cityRecord matches the subset of the GeoLite2-City schema we need.
type cityRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
}

// asnRecord matches the GeoLite2-ASN schema.
type asnRecord struct {
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// Open opens a GeoLite2-City mmdb file (and optionally a GeoLite2-ASN file if
// asnPath is non-empty). Returns a no-op *DB (not nil) on any error so callers
// need no nil-check — Lookup will simply return empty GeoInfo.
func Open(cityPath, asnPath string) (*DB, error) {
	db := &DB{}
	if cityPath == "" {
		return db, nil
	}
	r, err := maxminddb.Open(cityPath)
	if err != nil {
		return db, err
	}
	db.city = r

	if asnPath != "" {
		ar, err := maxminddb.Open(asnPath)
		if err == nil {
			db.asn = ar
		}
	}
	return db, nil
}

// Close releases the mmdb file handles.
func (d *DB) Close() {
	if d.city != nil {
		d.city.Close()
	}
	if d.asn != nil {
		d.asn.Close()
	}
}

// Lookup returns geographic metadata for the given IP string.
// Private/loopback addresses and any parse/lookup errors return empty GeoInfo.
func (d *DB) Lookup(ipStr string) GeoInfo {
	if d.city == nil {
		return GeoInfo{}
	}
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		return GeoInfo{}
	}

	var info GeoInfo

	var city cityRecord
	if err := d.city.Lookup(ip, &city); err == nil {
		info.CountryCode = city.Country.ISOCode
		if name, ok := city.City.Names["en"]; ok {
			info.City = name
		}
	}

	if d.asn != nil {
		var asn asnRecord
		if err := d.asn.Lookup(ip, &asn); err == nil {
			info.ASNOrg = asn.AutonomousSystemOrganization
		}
	}

	return info
}
