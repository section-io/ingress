package template

import (
	"encoding/json"
	"fmt"
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

// reduceByAlias reduces the incoming servers by incoming Alias value, joining multiple Hostname into outgoing Alias value
func reduceByAlias(servers []*ingress.Server) []*ingress.Server {
	// The fallback server `_` has no Alias, so this relies on us using an Alias
	// for all ingress objects so there is no overlap.
	rs := map[string]ingress.Server{}
	for _, srv := range servers {
		s := *srv //shallow copy seems acceptable for this scenario
		alias := s.Alias
		rsa, ok := rs[alias]
		if !ok {
			s.Alias = ""
			rs[alias] = s
		} else {
			if rsa.Alias == "" {
				rsa.Alias = s.Hostname
			} else {
				rsa.Alias = fmt.Sprintf("%s %s", rs[alias].Alias, s.Hostname)
			}
			rs[alias] = rsa
		}
	}

	fmtDomainName := func(name string) string {
		// If 'name' is a wildcard name, need to convert to a regex.
		// NOTE: we're only handling 1 level of wildcards system-wide at this time.
		if !strings.HasPrefix(name, "*.") {
			return name
		}
		regexName := "\"~^([a-z0-9\\-]{1,63})" + strings.ReplaceAll(name[1:], ".", "\\.") + "$\""
		return regexName
	}

	srv := make([]*ingress.Server, 0)
	for _, server := range rs {
		val := server
		if strings.HasPrefix(val.Hostname, "*.") || strings.Index(val.Alias, "*") > -1 {
			// Make a copy of server and convert wildcard names to regex.
			// Don't need a deep copy as we may only change Server and Alias
			val.Hostname = fmtDomainName(val.Hostname)
			aliases := strings.Split(val.Alias, " ")
			for i, alias := range aliases {
				aliases[i] = fmtDomainName(alias)
			}
			val.Alias = strings.Join(aliases, " ")
		}
		srv = append(srv, &val)
	}

	return srv
}
