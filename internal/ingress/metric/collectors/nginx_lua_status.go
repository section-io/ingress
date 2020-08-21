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

package collectors

import (
	"log"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/ingress-nginx/internal/nginx"
	"k8s.io/klog"
)

var (
	reCertCapacityBytes  = regexp.MustCompile(`cert_capacity_bytes: (\d+)`)
	reCertFreeSpaceBytes = regexp.MustCompile(`cert_free_space_bytes: (\d+)`)
	reCertLastFail       = regexp.MustCompile(`cert_last_fail: (\d+)`)
	reCertLastForcible   = regexp.MustCompile(`cert_last_forcible: (\d+)`)
	reCertLastSuccess    = regexp.MustCompile(`cert_last_success: (\d+)`)
	reCertOverflowTotal  = regexp.MustCompile(`cert_overflow_total: (\d+)`)
	reConfCapacityBytes  = regexp.MustCompile(`conf_capacity_bytes: (\d+)`)
	reConfFreeSpaceBytes = regexp.MustCompile(`conf_free_space_bytes: (\d+)`)
)

type (
	nginxLuaStatusCollector struct {
		scrapeChan chan scrapeRequest

		data *nginxLuaStatusData
	}

	nginxLuaStatusData struct {
		certificateLast          *prometheus.Desc
		certificateOverflowTotal *prometheus.Desc
		sharedDictionaryCapacity *prometheus.Desc
		sharedDictionaryFree     *prometheus.Desc
	}

	basicLuaStatus struct {
		CertificateCapacity      int
		CertificateFreeSpace     int
		CertificateLastFail      int
		CertificateLastForcible  int
		CertificateLastSuccess   int
		CertificateOverflowTotal int
		ConfigurationCapacity    int
		ConfigurationFreeSpace   int
	}
)

// NGINXLuaStatusCollector defines a LUA status collector interface
type NGINXLuaStatusCollector interface {
	prometheus.Collector

	Start()
	Stop()
}

// NewNGINXLuaStatus returns a new prometheus collector for the dynamic configuration+certificate LUA
func NewNGINXLuaStatus(podName, namespace, ingressClass string) (NGINXLuaStatusCollector, error) {
	p := nginxLuaStatusCollector{
		scrapeChan: make(chan scrapeRequest),
	}

	constLabels := prometheus.Labels{
		"controller_namespace": namespace,
		"controller_class":     ingressClass,
		"controller_pod":       podName,
	}

	p.data = &nginxLuaStatusData{
		certificateLast: prometheus.NewDesc(
			prometheus.BuildFQName(PrometheusNamespace, subSystem, "cert_count"),
			"number of certs in last configuration update state {success, forcible, fail}",
			[]string{"result"}, constLabels),

		certificateOverflowTotal: prometheus.NewDesc(
			prometheus.BuildFQName(PrometheusNamespace, subSystem, "cert_overflow_total"),
			"number of valid items removed forcibly when out of storage in the shared memory zone",
			nil, constLabels),

		sharedDictionaryCapacity: prometheus.NewDesc(
			prometheus.BuildFQName(PrometheusNamespace, subSystem, "dictionary_capacity"),
			"capacity in bytes for the shm-based dictionary",
			[]string{"name"}, constLabels),

		sharedDictionaryFree: prometheus.NewDesc(
			prometheus.BuildFQName(PrometheusNamespace, subSystem, "dictionary_free"),
			"free page size in bytes for the shm-based dictionary",
			[]string{"name"}, constLabels),
	}

	return p, nil
}

// Describe implements prometheus.Collector.
func (p nginxLuaStatusCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- p.data.certificateLast
	ch <- p.data.certificateOverflowTotal
	ch <- p.data.sharedDictionaryCapacity
	ch <- p.data.sharedDictionaryFree
}

// Collect implements prometheus.Collector.
func (p nginxLuaStatusCollector) Collect(ch chan<- prometheus.Metric) {
	req := scrapeRequest{results: ch, done: make(chan struct{})}
	p.scrapeChan <- req
	<-req.done
}

func (p nginxLuaStatusCollector) Start() {
	for req := range p.scrapeChan {
		ch := req.results
		p.scrape(ch)
		req.done <- struct{}{}
	}
}

func (p nginxLuaStatusCollector) Stop() {
	close(p.scrapeChan)
}

func parseLua(data string) *basicLuaStatus {
	return &basicLuaStatus{
		CertificateCapacity:      toInt(reCertCapacityBytes.FindStringSubmatch(data), 1),
		CertificateFreeSpace:     toInt(reCertFreeSpaceBytes.FindStringSubmatch(data), 1),
		CertificateLastFail:      toInt(reCertLastFail.FindStringSubmatch(data), 1),
		CertificateLastForcible:  toInt(reCertLastForcible.FindStringSubmatch(data), 1),
		CertificateLastSuccess:   toInt(reCertLastSuccess.FindStringSubmatch(data), 1),
		CertificateOverflowTotal: toInt(reCertOverflowTotal.FindStringSubmatch(data), 1),
		ConfigurationCapacity:    toInt(reConfCapacityBytes.FindStringSubmatch(data), 1),
		ConfigurationFreeSpace:   toInt(reConfFreeSpaceBytes.FindStringSubmatch(data), 1),
	}
}

// nginxStatusCollector scrape the nginx status
func (p nginxLuaStatusCollector) scrape(ch chan<- prometheus.Metric) {
	klog.V(3).Infof("start scraping socket: %v", nginx.LuaStatusPath)
	status, data, err := nginx.NewGetStatusRequest(nginx.LuaStatusPath)
	if err != nil {
		log.Printf("%v", err)
		klog.Warningf("unexpected error obtaining nginx lua status info: %v", err)
		return
	}

	if status < 200 || status >= 400 {
		klog.Warningf("unexpected error obtaining nginx lua status info (status %v)", status)
		return
	}

	s := parseLua(string(data))

	ch <- prometheus.MustNewConstMetric(p.data.certificateLast, prometheus.GaugeValue, float64(s.CertificateLastFail), "fail")
	ch <- prometheus.MustNewConstMetric(p.data.certificateLast, prometheus.GaugeValue, float64(s.CertificateLastForcible), "forcible")
	ch <- prometheus.MustNewConstMetric(p.data.certificateLast, prometheus.GaugeValue, float64(s.CertificateLastSuccess), "success")
	ch <- prometheus.MustNewConstMetric(p.data.certificateOverflowTotal, prometheus.CounterValue, float64(s.CertificateOverflowTotal))
	ch <- prometheus.MustNewConstMetric(p.data.sharedDictionaryCapacity, prometheus.GaugeValue, float64(s.CertificateCapacity), "certificate")
	ch <- prometheus.MustNewConstMetric(p.data.sharedDictionaryCapacity, prometheus.GaugeValue, float64(s.ConfigurationCapacity), "configuration")
	ch <- prometheus.MustNewConstMetric(p.data.sharedDictionaryFree, prometheus.GaugeValue, float64(s.CertificateFreeSpace), "certificate")
	ch <- prometheus.MustNewConstMetric(p.data.sharedDictionaryFree, prometheus.GaugeValue, float64(s.ConfigurationFreeSpace), "configuration")
}
