package template

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

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

// reduceByAlias redueses the incoming server blocks to a single
// server based on the alias
func reduceByAlias(servers []*ingress.Server) []*ingress.Server {
	rs := map[string]*ingress.Server{}
	for _, s := range servers {
		alias := s.Alias
		_, ok := rs[alias]
		if !ok {
			rs[alias] = s
		} else {
			rs[alias].Alias = fmt.Sprintf("%s %s", rs[alias].Alias, s.Hostname)
		}
	}

	srv := make([]*ingress.Server, 0)
	for _, server := range rs {
		srv = append(srv, server)
	}

	return srv
}
