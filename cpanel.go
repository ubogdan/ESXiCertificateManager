package main

import (
	"strings"

	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
)

func getZoneName(api cpanel.CpanelApi, name string) (string, error) {
	zones, err := api.FetchZones()
	if err != nil {
		return "", err
	}
	for _, zone := range zones.Data[0].Zones {
		if strings.HasSuffix(name, zone[0]) {
			return zone[0], nil
		}
	}
	return "", nil
}
