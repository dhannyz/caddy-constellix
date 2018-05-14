// Package dnsimple adapts the lego DNS Made Easy DNS provider
// for Caddy. Importing this package plugs it in.
package constellix

import (
	"errors"

	"github.com/dhannyz/caddy-constellix/dns"
	"github.com/mholt/caddy/caddytls"
)

func init() {
	caddytls.RegisterDNSProvider("constellix", NewDNSProvider)
}

// NewDNSProvider returns a new DNS Made Easy DNS challenge provider.
// The credentials are interpreted as follows:
//
// len(0): use credentials from environment
// len(3): credentials[0] = API Endpoint
//         credentials[1] = API key
//         credentials[2] = API secret
func NewDNSProvider(credentials ...string) (caddytls.ChallengeProvider, error) {
	switch len(credentials) {
	case 0:
		return constellix.NewDNSProvider()
	case 3:
		return constellix.NewDNSProviderCredentials(credentials[0], credentials[1], credentials[2])
	default:
		return nil, errors.New("invalid credentials length")
	}
}
