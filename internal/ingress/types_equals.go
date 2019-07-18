/*
Copyright 2017 The Kubernetes Authors.

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

package ingress

import (
	"k8s.io/ingress-nginx/internal/sets"
	"k8s.io/klog"
)

func logServers(servers []*Server, label string) {
	for idx, c1s := range servers {
		klog.Infof("Equal: %s server %v: %+v", label, idx, c1s.Hostname)
	}
}

func logBackends(backends []*Backend, label string) {
	for idx, b := range backends {
		klog.Infof("Equal: %s backend %v: %+v", label, idx, b.Name)
	}
}

// Equal tests for equality between two Configuration types
func (c1 *Configuration) Equal(c2 *Configuration) bool {
	if c1 == c2 {
		return true
	}
	if c1 == nil || c2 == nil {
		klog.Infof("Equal: c1 or c2 was nil")
		return false
	}

	match := compareBackends(c1.Backends, c2.Backends)
	if !match {
		klog.Infof("Equal: backends were not equal \n%v\n%v", c1.Backends, c2.Backends)
		logBackends(c1.Backends, "back1")
		logBackends(c2.Backends, "back2")
		return false
	}

	if len(c1.Servers) != len(c2.Servers) {
		klog.Infof("Equal: server length not the same. c1:%v items, c2:%v items", len(c1.Servers), len(c2.Servers))
		return false
	}

	// Servers are sorted
	for idx, c1s := range c1.Servers {
		if !c1s.Equal(c2.Servers[idx]) {
			klog.Infof("Equal: servers not sorted same")
			// logServers(c1.Servers, "c1")
			// logServers(c2.Servers, "c2")
			klog.Infof("servers:\ncls: %+v\nc2:%+v", c1.Servers[idx], c2.Servers[idx])
			return false
		}
	}

	match = compareL4Service(c1.TCPEndpoints, c2.TCPEndpoints)
	if !match {
		klog.Infof("Equal: l4 TCP service did not match")
		return false
	}

	match = compareL4Service(c1.UDPEndpoints, c2.UDPEndpoints)
	if !match {
		klog.Infof("Equal: l4 UDP did not match")
		return false
	}

	if len(c1.PassthroughBackends) != len(c2.PassthroughBackends) {
		klog.Infof("Equal: passThroughbackends length did not match")
		return false
	}

	for _, ptb1 := range c1.PassthroughBackends {
		found := false
		for _, ptb2 := range c2.PassthroughBackends {
			if ptb1.Equal(ptb2) {
				found = true
				break
			}
		}
		if !found {
			klog.Infof("Equal: passThroughbackends did not contain matching items")
			return false
		}
	}

	if c1.BackendConfigChecksum != c2.BackendConfigChecksum {
		klog.Infof("Equal: backendConfigChecksum did not match")
		return false
	}

	if c1.ControllerPodsCount != c2.ControllerPodsCount {
		klog.Infof("Equal: ControllerPodsCount did not match")
		return false
	}
	klog.Infof("Equal: success")
	return true
}

// Equal tests for equality between two Backend types
func (b1 *Backend) Equal(b2 *Backend) bool {
	if b1 == b2 {
		return true
	}
	if b1 == nil || b2 == nil {
		klog.Infof("Equal Backend: b1 or b2 was nil")
		return false
	}
	if b1.Name != b2.Name {
		klog.Infof("Equal Backend: b1 name (%v) did not match b2 name (%v)", b1.Name, b2.Name)
		return false
	}
	if b1.NoServer != b2.NoServer {
		return false
	}

	if b1.Service != b2.Service {
		if b1.Service == nil || b2.Service == nil {
			return false
		}
		if b1.Service.GetNamespace() != b2.Service.GetNamespace() {
			return false
		}
		if b1.Service.GetName() != b2.Service.GetName() {
			return false
		}
	}

	if b1.Port != b2.Port {
		return false
	}
	if !(&b1.SecureCACert).Equal(&b2.SecureCACert) {
		return false
	}
	if b1.SSLPassthrough != b2.SSLPassthrough {
		return false
	}
	if !(&b1.SessionAffinity).Equal(&b2.SessionAffinity) {
		return false
	}
	if b1.UpstreamHashBy != b2.UpstreamHashBy {
		return false
	}
	if b1.LoadBalancing != b2.LoadBalancing {
		return false
	}

	match := compareEndpoints(b1.Endpoints, b2.Endpoints)
	if !match {
		klog.Infof("Equal Backend: endpoints did not match. b1.Name:%v  b2.Name:%v", b1.Name, b2.Name)
		return false
	}

	if !b1.TrafficShapingPolicy.Equal(b2.TrafficShapingPolicy) {
		return false
	}

	match = sets.StringElementsMatch(b1.AlternativeBackends, b2.AlternativeBackends)
	if !match {
		return false
	}

	return true
}

// Equal tests for equality between two SessionAffinityConfig types
func (sac1 *SessionAffinityConfig) Equal(sac2 *SessionAffinityConfig) bool {
	if sac1 == sac2 {
		return true
	}
	if sac1 == nil || sac2 == nil {
		return false
	}
	if sac1.AffinityType != sac2.AffinityType {
		return false
	}
	if !(&sac1.CookieSessionAffinity).Equal(&sac2.CookieSessionAffinity) {
		return false
	}

	return true
}

// Equal tests for equality between two CookieSessionAffinity types
func (csa1 *CookieSessionAffinity) Equal(csa2 *CookieSessionAffinity) bool {
	if csa1 == csa2 {
		return true
	}
	if csa1 == nil || csa2 == nil {
		return false
	}
	if csa1.Name != csa2.Name {
		return false
	}
	if csa1.Path != csa2.Path {
		return false
	}
	if csa1.Expires != csa2.Expires {
		return false
	}
	if csa1.MaxAge != csa2.MaxAge {
		return false
	}

	return true
}

//Equal checks the equality between UpstreamByConfig types
func (u1 *UpstreamHashByConfig) Equal(u2 *UpstreamHashByConfig) bool {
	if u1 == u2 {
		return true
	}
	if u1 == nil || u2 == nil {
		return false
	}
	if u1.UpstreamHashBy != u2.UpstreamHashBy {
		return false
	}
	if u1.UpstreamHashBySubset != u2.UpstreamHashBySubset {
		return false
	}
	if u1.UpstreamHashBySubsetSize != u2.UpstreamHashBySubsetSize {
		return false
	}

	return true
}

// Equal checks the equality against an Endpoint
func (e1 *Endpoint) Equal(e2 *Endpoint) bool {
	if e1 == e2 {
		return true
	}
	if e1 == nil || e2 == nil {
		klog.Infof("Equal Endpoint: got nil endpoint)")
		return false
	}
	if e1.Address != e2.Address {
		klog.Infof("Equal Endpoint: Address not match e1 %v  e2 %v)", e1.Address, e2.Address)
		return false
	}
	if e1.Port != e2.Port {
		klog.Infof("Equal Endpoint: Port not match e1 %v  e2 %v)", e1.Port, e2.Port)
		return false
	}

	if e1.Target != e2.Target {
		if e1.Target == nil || e2.Target == nil {
			klog.Infof("Equal Endpoint: got nil Target)")
			return false
		}
		if e1.Target.UID != e2.Target.UID {
			klog.Infof("Equal Endpoint: target.UID not match e1 %v  e2 %v)", e1.Target.UID, e2.Target.UID)
			return false
		}
		if e1.Target.ResourceVersion != e2.Target.ResourceVersion {
			klog.Infof("Equal Endpoint: target.ResourceVersion not match e1 %v  e2 %v)", e1.Target.ResourceVersion, e2.Target.ResourceVersion)
			return false
		}
	}

	return true
}

// Equal checks for equality between two TrafficShapingPolicies
func (tsp1 TrafficShapingPolicy) Equal(tsp2 TrafficShapingPolicy) bool {
	if tsp1.Weight != tsp2.Weight {
		return false
	}
	if tsp1.Header != tsp2.Header {
		return false
	}
	if tsp1.HeaderValue != tsp2.HeaderValue {
		return false
	}
	if tsp1.Cookie != tsp2.Cookie {
		return false
	}

	return true
}

// Equal tests for equality between two Server types
func (s1 *Server) Equal(s2 *Server) bool {
	if s1 == s2 {
		return true
	}
	if s1 == nil || s2 == nil {
		return false
	}
	if s1.Hostname != s2.Hostname {
		klog.Infof("Equal: hostname not match \n%v\n%v", s1.Hostname, s2.Hostname)
		return false
	}
	if s1.SSLPassthrough != s2.SSLPassthrough {
		return false
	}
	if !(&s1.SSLCert).Equal(&s2.SSLCert) {
		klog.Infof("Equal: SSLCert not match \n%v\n%v", s1.SSLCert, s2.SSLCert)
		return false
	}
	if s1.Alias != s2.Alias {
		klog.Infof("Equal: Alias not match \n%v\n%v", s1.Alias, s2.Alias)
		return false
	}
	if s1.RedirectFromToWWW != s2.RedirectFromToWWW {
		klog.Infof("Equal: RedirectFromToWWW not match \n%v\n%v", s1.RedirectFromToWWW, s2.RedirectFromToWWW)
		return false
	}
	if !(&s1.CertificateAuth).Equal(&s2.CertificateAuth) {
		klog.Infof("Equal: CertificateAuth not match \n%v\n%v", s1.CertificateAuth, s2.CertificateAuth)
		return false
	}
	// if s1.ServerSnippet != s2.ServerSnippet {
	// 	klog.Infof("Equal: ServerSnippet not match \n%v\n%v", s1.ServerSnippet, s2.ServerSnippet)
	// 	return false
	// }
	if s1.SSLCiphers != s2.SSLCiphers {
		klog.Infof("Equal: SSLCiphers not match \n%v\n%v", s1.SSLCiphers, s2.SSLCiphers)
		return false
	}
	if s1.AuthTLSError != s2.AuthTLSError {
		klog.Infof("Equal: AuthTLSError not match \n%v\n%v", s1.AuthTLSError, s2.AuthTLSError)
		return false
	}

	if len(s1.Locations) != len(s2.Locations) {
		klog.Infof("Equal:Server Locations not match \n%v\n%v", s1.Locations, s2.Locations)
		return false
	}

	// Location are sorted
	for idx, s1l := range s1.Locations {
		if !s1l.Equal(s2.Locations[idx]) {
			klog.Infof("Equal:Server Locations are not sorted the same  \n%v\n%v", s1l, s2.Locations[idx])
			return false
		}
	}

	return true
}

// Equal tests for equality between two Location types
func (l1 *Location) Equal(l2 *Location) bool {
	if l1 == l2 {
		return true
	}
	if l1 == nil || l2 == nil {
		klog.Infof("Equal:Location l1 or l2 was nil.")
		return false
	}
	if l1.Path != l2.Path {
		klog.Infof("Equal:Location path is not equal. l1:%v  l2:%v", l1.Path, l2.Path)
		return false
	}
	if l1.IsDefBackend != l2.IsDefBackend {
		klog.Infof("Equal:Location IsDefBackend is not equal. l1:%v  l2:%v", l1.IsDefBackend, l2.IsDefBackend)
		return false
	}
	if l1.Backend != l2.Backend {
		klog.Infof("Equal:Location Backend is not equal. l1:%v  l2:%v", l1.Backend, l2.Backend)
		return false
	}

	if l1.Service != l2.Service {
		if l1.Service == nil || l2.Service == nil {
			klog.Infof("Equal:Location l1 or l2 Service was nil.")
			return false
		}
		if l1.Service.GetNamespace() != l2.Service.GetNamespace() {
			klog.Infof("Equal:Location service namespace is not equal. l1:%v  l2:%v", l1.Service.GetNamespace(), l2.Service.GetNamespace())
			return false
		}
		if l1.Service.GetName() != l2.Service.GetName() {
			klog.Infof("Equal:Location Service.GetName is not equal. l1:%v  l2:%v", l1.Service.GetName(), l2.Service.GetName())
			return false
		}
	}

	if l1.Port.StrVal != l2.Port.StrVal {
		klog.Infof("Equal:Location Port StrVal not equal. l1:%v  l2:%v", l1.Port.StrVal, l2.Port.StrVal)
		return false
	}
	if !(&l1.BasicDigestAuth).Equal(&l2.BasicDigestAuth) {
		return false
	}
	if l1.Denied != l2.Denied {
		return false
	}
	if !(&l1.CorsConfig).Equal(&l2.CorsConfig) {
		return false
	}
	if !(&l1.ExternalAuth).Equal(&l2.ExternalAuth) {
		return false
	}
	if l1.HTTP2PushPreload != l2.HTTP2PushPreload {
		return false
	}
	if !(&l1.RateLimit).Equal(&l2.RateLimit) {
		return false
	}
	if !(&l1.Redirect).Equal(&l2.Redirect) {
		return false
	}
	if !(&l1.Rewrite).Equal(&l2.Rewrite) {
		klog.Infof("Equal:Location rewrite not equal. l1:%v  l2:%v", &l1.Rewrite, &l2.Rewrite)
		return false
	}
	if !(&l1.Whitelist).Equal(&l2.Whitelist) {
		return false
	}
	if !(&l1.Proxy).Equal(&l2.Proxy) {
		return false
	}
	if l1.UsePortInRedirects != l2.UsePortInRedirects {
		return false
	}
	if l1.ConfigurationSnippet != l2.ConfigurationSnippet {
		klog.Infof("Equal:Location ConfigurationSnippet not equal. l1:%v  l2:%v", l1.ConfigurationSnippet, l2.ConfigurationSnippet)
		return false
	}
	if l1.ClientBodyBufferSize != l2.ClientBodyBufferSize {
		return false
	}
	if l1.UpstreamVhost != l2.UpstreamVhost {
		return false
	}
	if l1.XForwardedPrefix != l2.XForwardedPrefix {
		return false
	}
	if !(&l1.Connection).Equal(&l2.Connection) {
		return false
	}
	if !(&l1.Logs).Equal(&l2.Logs) {
		return false
	}
	if !(&l1.LuaRestyWAF).Equal(&l2.LuaRestyWAF) {
		return false
	}

	if !(&l1.InfluxDB).Equal(&l2.InfluxDB) {
		return false
	}

	if l1.BackendProtocol != l2.BackendProtocol {
		return false
	}

	match := compareInts(l1.CustomHTTPErrors, l2.CustomHTTPErrors)
	if !match {
		return false
	}

	if !(&l1.ModSecurity).Equal(&l2.ModSecurity) {
		return false
	}

	if l1.Satisfy != l2.Satisfy {
		return false
	}

	if l1.DefaultBackendUpstreamName != l2.DefaultBackendUpstreamName {
		return false
	}

	return true
}

// Equal tests for equality between two SSLPassthroughBackend types
func (ptb1 *SSLPassthroughBackend) Equal(ptb2 *SSLPassthroughBackend) bool {
	if ptb1 == ptb2 {
		return true
	}
	if ptb1 == nil || ptb2 == nil {
		return false
	}
	if ptb1.Backend != ptb2.Backend {
		return false
	}
	if ptb1.Hostname != ptb2.Hostname {
		return false
	}
	if ptb1.Port != ptb2.Port {
		return false
	}

	if ptb1.Service != ptb2.Service {
		if ptb1.Service == nil || ptb2.Service == nil {
			return false
		}
		if ptb1.Service.GetNamespace() != ptb2.Service.GetNamespace() {
			return false
		}
		if ptb1.Service.GetName() != ptb2.Service.GetName() {
			return false
		}
	}

	return true
}

// Equal tests for equality between two L4Service types
func (e1 *L4Service) Equal(e2 *L4Service) bool {
	if e1 == e2 {
		return true
	}
	if e1 == nil || e2 == nil {
		return false
	}
	if e1.Port != e2.Port {
		return false
	}
	if !(&e1.Backend).Equal(&e2.Backend) {
		return false
	}

	match := compareEndpoints(e1.Endpoints, e2.Endpoints)
	if !match {
		return false
	}

	return true
}

// Equal tests for equality between two L4Backend types
func (l4b1 *L4Backend) Equal(l4b2 *L4Backend) bool {
	if l4b1 == l4b2 {
		return true
	}
	if l4b1 == nil || l4b2 == nil {
		return false
	}
	if l4b1.Port != l4b2.Port {
		return false
	}
	if l4b1.Name != l4b2.Name {
		return false
	}
	if l4b1.Namespace != l4b2.Namespace {
		return false
	}
	if l4b1.Protocol != l4b2.Protocol {
		return false
	}

	return true
}

// Equal tests for equality between two SSLCert types
func (s1 *SSLCert) Equal(s2 *SSLCert) bool {
	if s1 == s2 {
		return true
	}
	if s1 == nil || s2 == nil {
		return false
	}
	if s1.PemFileName != s2.PemFileName {
		klog.Infof("SSLCert Equal: PemFileName not match: \n%v\n%v", s1.PemFileName, s2.PemFileName)
		return false
	}
	if s1.PemSHA != s2.PemSHA {
		return false
	}
	if !s1.ExpireTime.Equal(s2.ExpireTime) {
		return false
	}
	if s1.FullChainPemFileName != s2.FullChainPemFileName {
		klog.Infof("SSLCert Equal: FullChainPemFileName not match: \n%v\n%v", s1.FullChainPemFileName, s2.FullChainPemFileName)
		return false
	}
	if s1.PemCertKey != s2.PemCertKey {
		klog.Infof("SSLCert Equal: PemCertKey not match: \n%v\n%v", s1.PemCertKey, s2.PemCertKey)
		return false
	}

	match := sets.StringElementsMatch(s1.CN, s2.CN)
	if !match {
		return false
	}

	return true
}

var compareEndpointsFunc = func(e1, e2 interface{}) bool {
	ep1, ok := e1.(Endpoint)
	if !ok {
		return false
	}

	ep2, ok := e2.(Endpoint)
	if !ok {
		return false
	}

	return (&ep1).Equal(&ep2)
}

func compareEndpoints(a, b []Endpoint) bool {
	return sets.Compare(a, b, compareEndpointsFunc)
}

var compareBackendsFunc = func(e1, e2 interface{}) bool {
	b1, ok := e1.(*Backend)
	if !ok {
		klog.Infof("compareBackends: e1 type not Backend")
		return false
	}

	b2, ok := e2.(*Backend)
	if !ok {
		klog.Infof("compareBackends: e2 type not Backend")
		return false
	}
	// klog.Infof("compareBackends: \nb1: %v\nb2: %v", b1, b2)
	return b1.Equal(b2)
}

func compareBackends(a, b []*Backend) bool {
	return sets.Compare(a, b, compareBackendsFunc)
}

var compareIntsFunc = func(e1, e2 interface{}) bool {
	b1, ok := e1.(int)
	if !ok {
		return false
	}

	b2, ok := e2.(int)
	if !ok {
		return false
	}

	return b1 == b2
}

func compareInts(a, b []int) bool {
	return sets.Compare(a, b, compareIntsFunc)
}

var compareL4ServiceFunc = func(e1, e2 interface{}) bool {
	b1, ok := e1.(L4Service)
	if !ok {
		return false
	}

	b2, ok := e2.(L4Service)
	if !ok {
		return false
	}

	return (&b1).Equal(&b2)
}

func compareL4Service(a, b []L4Service) bool {
	return sets.Compare(a, b, compareL4ServiceFunc)
}
