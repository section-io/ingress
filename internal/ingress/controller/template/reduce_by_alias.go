package template

import (
	"encoding/json"
	"io/ioutil"
	"strings"

	"k8s.io/ingress-nginx/internal/ingress"
)

// toJson takes the value and write it as JSON to /etc/nginx/input.json
func toJson(input interface{}) string {
	bin, err := json.MarshalIndent(input, "  ", "")
	if err != nil {
		return err.Error()
	}

	// www-data has permissions to write to /tmp
	err = ioutil.WriteFile("/etc/nginx/input.json", bin, 0777)
	if err != nil {
		return err.Error()
	}
	return ""
}

// reduceByAlias reduces the incoming server blocks to a single
// server block based on the alias of a server instance.
func reduceByAlias(servers []*ingress.Server) []*ingress.Server {
	// The fallback server `_` has no Alias, so this relies on us using an Alias
	// for all ingress objects so there is no overlap.
	rs := map[string]ingress.Server{}
	for _, srv := range servers {
		s := *srv //shallow copy seems acceptable for this scenario
		alias := strings.Join(s.Aliases, " ")
		rsa, ok := rs[alias]
		if !ok {
			rs[alias] = s
		} else {
			rsa.Aliases = append(s.Aliases, s.Hostname)
			rs[alias] = rsa
		}
	}

	srv := make([]*ingress.Server, 0)
	for _, server := range rs {
		val := server
		srv = append(srv, &val)
	}

	return srv
}
