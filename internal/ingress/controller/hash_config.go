package controller

import (
	"hash/fnv"

	"k8s.io/ingress-nginx/internal/ingress"
)

// HashConfig Creates a hash of the Configuration using fnv
func HashConfig(config ingress.Configuration) uint64 {
	hash := fnv.New64()

	for _, b := range config.Backends {
		hash.Write([]byte(b.Name))
	}

	for _, s := range config.Servers {
		hash.Write([]byte(s.Hostname))
	}

	return hash.Sum64()
}