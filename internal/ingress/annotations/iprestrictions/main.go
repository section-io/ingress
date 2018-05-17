/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package iprestrictions

import (
	"sort"
	"strings"

	"github.com/golang/glog"
	"github.com/pkg/errors"

	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/ingress-nginx/internal/net"

	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	ing_errors "k8s.io/ingress-nginx/internal/ingress/errors"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

// SourceRange returns the CIDR
type SourceRange struct {
	CIDR        []string `json:"cidr,omitempty"`
	IsWhitelist bool     `json:"isWhitelist"`
}

// Equal tests for equality between two SourceRange types
func (sr1 *SourceRange) Equal(sr2 *SourceRange) bool {
	if sr1 == sr2 {
		return true
	}
	if sr1 == nil || sr2 == nil {
		return false
	}

	if len(sr1.CIDR) != len(sr2.CIDR) {
		return false
	}

	for _, s1l := range sr1.CIDR {
		found := false
		for _, sl2 := range sr2.CIDR {
			if s1l == sl2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

type iprestrictions struct {
	r resolver.Resolver
}

// NewParser creates a new whitelist annotation parser
func NewParser(r resolver.Resolver) parser.IngressAnnotation {
	return iprestrictions{r}
}

func getDefaultRange(a iprestrictions) *SourceRange {
	defBackend := a.r.GetDefaultBackend()
	sort.Strings(defBackend.WhitelistSourceRange)

	if len(defBackend.BlacklistSourceRange) > 0 {
		if len(defBackend.WhitelistSourceRange) > 0 {
			glog.Warningf("Ignoring whitelist-source-range from configmap because blacklist-source-range is set")
		}
		return &SourceRange{CIDR: defBackend.BlacklistSourceRange, IsWhitelist: false}
	} else {
		return &SourceRange{CIDR: defBackend.WhitelistSourceRange, IsWhitelist: true}
	}
}

// ParseAnnotations parses the annotations contained in the ingress
// rule used to limit access to certain client addresses or networks.
// Multiple ranges can specified using commas as separator
// e.g. `18.0.0.0/8,56.0.0.0/8`
func (a iprestrictions) Parse(ing *extensions.Ingress) (interface{}, error) {

	var isWhitelist bool
	val, err := parser.GetStringAnnotation("blacklist-source-range", ing)
	//Check the blacklist-source-range first, if this is not set, see if a whitelist-source-range is set
	if err == ing_errors.ErrMissingAnnotations {

		val, err = parser.GetStringAnnotation("whitelist-source-range", ing)
		if err == ing_errors.ErrMissingAnnotations {
			//If neither are set return the default blacklist or whitelist from the configmap, blacklist trumps whitelist
			return getDefaultRange(a), nil
		} else {
			isWhitelist = true
		}

	} else {
		isWhitelist = false
		_, err = parser.GetStringAnnotation("whitelist-source-range", ing)
		if err != ing_errors.ErrMissingAnnotations {
			glog.Warningf("Ignoring whitelist-source-range on ingress %v because blacklist-source-range is set", ing.ObjectMeta.Name)
		}
	}

	values := strings.Split(val, ",")
	ipnets, ips, err := net.ParseIPNets(values...)
	if err != nil && len(ips) == 0 {
		return getDefaultRange(a), ing_errors.LocationDenied{
			Reason: errors.Wrap(err, "the annotation does not contain a valid IP address or network"),
		}
	}

	cidrs := []string{}
	for k := range ipnets {
		cidrs = append(cidrs, k)
	}
	for k := range ips {
		cidrs = append(cidrs, k)
	}

	sort.Strings(cidrs)

	return &SourceRange{cidrs, isWhitelist}, nil
}
