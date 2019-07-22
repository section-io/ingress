package controller

import (
	"io"
	"k8s.io/ingress-nginx/internal/ingress/annotations/auth"
	"k8s.io/ingress-nginx/internal/ingress/annotations/authreq"
	"k8s.io/ingress-nginx/internal/ingress/annotations/authtls"
	"k8s.io/ingress-nginx/internal/ingress/annotations/cors"
	"strconv"

	"k8s.io/ingress-nginx/internal/ingress/annotations/proxy"
	"k8s.io/ingress-nginx/internal/ingress/annotations/ratelimit"

	"hash/fnv"
	"k8s.io/ingress-nginx/internal/ingress"
)

// HashConfig Creates a hash of the Configuration using fnv
// It walks the values, so may need to be updated as underlying structs change
func HashConfig(config ingress.Configuration) uint64 {
	hash := fnv.New64()
	writeConfig(config, hash)
	return hash.Sum64()
}

func writeString(a string, h io.Writer) {
	h.Write([]byte(a))
}

func writeInt(a int, h io.Writer) {
	h.Write([]byte(strconv.Itoa(a)))
}

func writeBool(a bool, h io.Writer) {
	if a {
		h.Write([]byte("1"))
	} else {
		h.Write([]byte("0"))
	}
}

// Equal tests for equality between two Configuration types
func writeConfig(c ingress.Configuration, hash io.Writer) {
	// check backends
	for _, b := range c.Backends {
		writeBackend(*b, hash)
	}

	// Check Servers
	for _, s := range c.Servers {
		writeServer(*s, hash)
	}

	// check l4 services
	for _, s := range c.TCPEndpoints {
		writeL4Service(s, hash)
	}

	for _, s := range c.UDPEndpoints {
		writeL4Service(s, hash)
	}

	// check passthroughBackends
	for _, s := range c.PassthroughBackends {
		writeSSLPassthroughBackend(*s, hash)
	}

	//backendConfigChecksum
	hash.Write([]byte(c.BackendConfigChecksum))

	//ControllerPodsCount
	hash.Write([]byte(strconv.Itoa(c.ControllerPodsCount)))
}

func writeBackend(b ingress.Backend, hash io.Writer) {
	writeString(b.Name, hash)

	writeBool(b.NoServer, hash)

	writeString(b.Service.GetNamespace(), hash)
	writeString(b.Service.GetName(), hash)

	writeInt(b.Port.IntValue(), hash)

	writeString(b.SecureCACert.Secret, hash)
	writeString(b.SecureCACert.CAFileName, hash)
	writeString(b.SecureCACert.PemSHA, hash)

	writeBool(b.SSLPassthrough, hash)

	writeSessionAffinityConfig(b.SessionAffinity, hash)

	writeUpstreamhashByConfig(b.UpstreamHashBy, hash)

	writeString(b.LoadBalancing, hash)

	for _, e := range b.Endpoints {
		writeEndpoint(e, hash)
	}

	writeTrafficShapingPolicy(b.TrafficShapingPolicy, hash)

	for _, item := range b.AlternativeBackends {
		writeString(item, hash)
	}
}

func writeSessionAffinityConfig(sac ingress.SessionAffinityConfig, hash io.Writer) {
	writeString(sac.AffinityType, hash)

	writeCookieSessionAffinity(sac.CookieSessionAffinity, hash)
}

func writeCookieSessionAffinity(csa ingress.CookieSessionAffinity, hash io.Writer) {
	writeString(csa.Name, hash)
	writeString(csa.Expires, hash)
	writeString(csa.MaxAge, hash)
	writeString(csa.Path, hash)
}

func writeUpstreamhashByConfig(u ingress.UpstreamHashByConfig, hash io.Writer) {
	writeString(u.UpstreamHashBy, hash)

	writeBool(u.UpstreamHashBySubset, hash)

	writeInt(u.UpstreamHashBySubsetSize, hash)
}

func writeEndpoint(e ingress.Endpoint, hash io.Writer) {
	writeString(e.Address, hash)

	writeString(e.Port, hash)

	writeString(e.Target.String(), hash)
}

func writeTrafficShapingPolicy(tsp ingress.TrafficShapingPolicy, hash io.Writer) {
	writeInt(tsp.Weight, hash)

	writeString(tsp.Header, hash)

	writeString(tsp.HeaderValue, hash)

	writeString(tsp.Cookie, hash)
}

func writeServer(s ingress.Server, hash io.Writer) {
	writeString(s.Hostname, hash)

	writeBool(s.SSLPassthrough, hash)

	writeSSLCert(s.SSLCert, hash)

	writeString(s.Alias, hash)

	writeBool(s.RedirectFromToWWW, hash)

	writeCertificateAuth(s.CertificateAuth, hash)

	writeString(s.ServerSnippet, hash)

	writeString(s.SSLCiphers, hash)

	writeString(s.AuthTLSError, hash)

	for _, l := range s.Locations {
		writeLocation(*l, hash)
	}
}

func writeCertificateAuth(s authtls.Config, hash io.Writer) {
	writeString(s.Secret, hash)
	writeString(s.CAFileName, hash)
	writeString(s.PemSHA, hash)
	writeString(s.VerifyClient, hash)
	writeString(s.ErrorPage, hash)
	writeString(s.AuthTLSError, hash)
	writeString(s.AuthSSLCert.CAFileName, hash)
	writeString(s.AuthSSLCert.PemSHA, hash)
	writeString(s.AuthSSLCert.Secret, hash)
	writeInt(s.ValidationDepth, hash)
	writeBool(s.PassCertToUpstream, hash)
}

func writeCorsConfig(c cors.Config, hash io.Writer) {
	writeString(c.CorsAllowOrigin, hash)
	writeBool(c.CorsEnabled, hash)
	writeString(c.CorsAllowMethods, hash)
	writeString(c.CorsAllowHeaders, hash)
	writeBool(c.CorsAllowCredentials, hash)
	writeInt(c.CorsMaxAge, hash)
}

func writeExternalAuth(l authreq.Config, hash io.Writer) {
	writeString(l.URL, hash)
	writeString(l.Host, hash)
	writeString(l.SigninURL, hash)
	writeString(l.Method, hash)
	writeString(l.RequestRedirect, hash)
	writeString(l.AuthSnippet, hash)
	for _, head := range l.ResponseHeaders {
		writeString(head, hash)
	}
}

func writeRateLimit(r ratelimit.Config, hash io.Writer) {
	writeString(r.Name, hash)
	writeString(r.ID, hash)
	writeInt(r.LimitRate, hash)
	writeInt(r.LimitRateAfter, hash)
	writeZone(r.Connections, hash)
	writeZone(r.RPS, hash)
	writeZone(r.RPM, hash)
	for _, i := range r.Whitelist {
		writeString(i, hash)
	}
}

func writeZone(z ratelimit.Zone, hash io.Writer) {
	writeString(z.Name, hash)
	writeInt(z.Limit, hash)
	writeInt(z.SharedSize, hash)
	writeInt(z.Burst, hash)
}

func writeProxy(p proxy.Config, hash io.Writer) {
	writeString(p.BodySize, hash)
	writeString(p.BufferSize, hash)
	writeString(p.CookieDomain, hash)
	writeString(p.CookiePath, hash)
	writeString(p.NextUpstream, hash)
	writeString(p.ProxyRedirectFrom, hash)
	writeString(p.ProxyRedirectTo, hash)
	writeString(p.RequestBuffering, hash)
	writeString(p.ProxyBuffering, hash)
	writeInt(p.ConnectTimeout, hash)
	writeInt(p.SendTimeout, hash)
	writeInt(p.ReadTimeout, hash)
	writeInt(p.BuffersNumber, hash)
	writeInt(p.NextUpstreamTries, hash)
}

func writeAuthTLSConfig(a auth.Config, hash io.Writer) {
	writeString(a.Type, hash)
	writeString(a.Realm, hash)
	writeString(a.File, hash)
	writeString(a.FileSHA, hash)
	writeString(a.Secret, hash)
	writeBool(a.Secured, hash)
}

func writeLocation(l ingress.Location, hash io.Writer) {
	writeString(l.Path, hash)

	writeBool(l.IsDefBackend, hash)

	writeString(l.Backend, hash)

	writeString(l.Service.GetNamespace(), hash)
	writeString(l.Service.GetName(), hash)

	writeString(l.Port.StrVal, hash)

	writeAuthTLSConfig(l.BasicDigestAuth, hash)

	denied := ""
	if l.Denied != nil {
		denied = *l.Denied
	}
	writeString(denied, hash)

	writeCorsConfig(l.CorsConfig, hash)

	writeExternalAuth(l.ExternalAuth, hash)

	writeBool(l.HTTP2PushPreload, hash)

	writeRateLimit(l.RateLimit, hash)

	writeString(l.Redirect.URL, hash)
	writeBool(l.Redirect.FromToWWW, hash)
	writeInt(l.Redirect.Code, hash)

	writeString(l.Rewrite.Target, hash)
	writeString(l.Rewrite.AppRoot, hash)
	writeBool(l.Rewrite.UseRegex, hash)
	writeBool(l.Rewrite.ForceSSLRedirect, hash)
	writeBool(l.Rewrite.SSLRedirect, hash)

	for _, wl := range l.Whitelist.CIDR {
		writeString(wl, hash)
	}

	writeProxy(l.Proxy, hash)

	writeBool(l.UsePortInRedirects, hash)

	writeString(l.ConfigurationSnippet, hash)

	writeString(l.ClientBodyBufferSize, hash)

	writeString(l.UpstreamVhost, hash)

	writeString(l.XForwardedPrefix, hash)

	writeString(l.Connection.Header, hash)
	writeBool(l.Connection.Enabled, hash)

	writeBool(l.Logs.Access, hash)
	writeBool(l.Logs.Rewrite, hash)

	writeString(l.LuaRestyWAF.Mode, hash)
	writeString(l.LuaRestyWAF.ExtraRulesetString, hash)
	writeBool(l.LuaRestyWAF.Debug, hash)
	writeBool(l.LuaRestyWAF.AllowUnknownContentTypes, hash)
	writeBool(l.LuaRestyWAF.ProcessMultipartBody, hash)
	writeInt(l.LuaRestyWAF.ScoreThreshold, hash)
	for _, i := range l.LuaRestyWAF.IgnoredRuleSets {
		writeString(i, hash)
	}

	writeString(l.InfluxDB.InfluxDBMeasurement, hash)
	writeString(l.InfluxDB.InfluxDBPort, hash)
	writeString(l.InfluxDB.InfluxDBHost, hash)
	writeString(l.InfluxDB.InfluxDBServerName, hash)
	writeBool(l.InfluxDB.InfluxDBEnabled, hash)

	writeString(l.BackendProtocol, hash)

	for _, i := range l.CustomHTTPErrors {
		writeInt(i, hash)
	}

	writeString(l.ModSecurity.TransactionID, hash)
	writeString(l.ModSecurity.Snippet, hash)
	writeBool(l.ModSecurity.Enable, hash)
	writeBool(l.ModSecurity.OWASPRules, hash)

	writeString(l.Satisfy, hash)

	writeString(l.DefaultBackendUpstreamName, hash)

}

func writeSSLPassthroughBackend(p ingress.SSLPassthroughBackend, hash io.Writer) {
	writeString(p.Backend, hash)

	writeString(p.Hostname, hash)

	writeString(p.Port.StrVal, hash)

	writeString(p.Service.GetNamespace(), hash)
	writeString(p.Service.GetName(), hash)

}

func writeL4Service(s ingress.L4Service, hash io.Writer) {
	writeInt(s.Port, hash)

	writeL4Backend(s.Backend, hash)

	for _, e := range s.Endpoints {
		writeEndpoint(e, hash)
	}
}

func writeL4Backend(b ingress.L4Backend, hash io.Writer) {
	writeString(b.Port.StrVal, hash)

	writeString(b.Name, hash)

	writeString(b.Namespace, hash)

	hash.Write([]byte(b.Protocol))
}

func writeSSLCert(s ingress.SSLCert, hash io.Writer) {
	writeString(s.PemFileName, hash)

	writeString(s.PemSHA, hash)

	writeString(s.ExpireTime.String(), hash)

	writeString(s.FullChainPemFileName, hash)

	writeString(s.PemCertKey, hash)

	for _, cn := range s.CN {
		writeString(cn, hash)
	}
}
