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
	"math"
	"regexp"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/ingress-nginx/internal/nginx"
	"k8s.io/klog"
)

var (
	reCertCapacityBytes  = regexp.MustCompile(`cert_capacity_bytes: (\d+)`)
	reCertFreeSpaceBytes = regexp.MustCompile(`cert_free_space_bytes: (\d+)`)
	reCertLastBytes      = regexp.MustCompile(`cert_last_bytes: (\d+)`)
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
		certificateLastBytes     *prometheus.Desc
		certificateOverflowTotal *prometheus.Desc
		sharedDictionaryCapacity *prometheus.Desc
		sharedDictionaryFree     *prometheus.Desc
	}

	basicLuaStatus struct {
		CertificateCapacity      float64
		CertificateFreeSpace     float64
		CertificateLastBytes     float64
		CertificateLastFail      float64
		CertificateLastForcible  float64
		CertificateLastSuccess   float64
		CertificateOverflowTotal float64
		ConfigurationCapacity    float64
		ConfigurationFreeSpace   float64
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

		certificateLastBytes: prometheus.NewDesc(
			prometheus.BuildFQName(PrometheusNamespace, subSystem, "cert_bytes"),
			"size in bytes of last last configuration update",
			nil, constLabels),

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
	ch <- p.data.certificateLastBytes
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

func toFloat64(data []string, pos int) float64 {
	if len(data) == 0 {
		return math.NaN()
	}
	if pos > len(data) {
		return math.NaN()
	}
	if v, err := strconv.ParseFloat(data[pos], 64); err == nil {
		return v
	}
	return math.NaN()
}

func parseLua(data string) *basicLuaStatus {
	return &basicLuaStatus{
		CertificateCapacity:      toFloat64(reCertCapacityBytes.FindStringSubmatch(data), 1),
		CertificateFreeSpace:     toFloat64(reCertFreeSpaceBytes.FindStringSubmatch(data), 1),
		CertificateLastBytes:     toFloat64(reCertLastBytes.FindStringSubmatch(data), 1),
		CertificateLastFail:      toFloat64(reCertLastFail.FindStringSubmatch(data), 1),
		CertificateLastForcible:  toFloat64(reCertLastForcible.FindStringSubmatch(data), 1),
		CertificateLastSuccess:   toFloat64(reCertLastSuccess.FindStringSubmatch(data), 1),
		CertificateOverflowTotal: toFloat64(reCertOverflowTotal.FindStringSubmatch(data), 1),
		ConfigurationCapacity:    toFloat64(reConfCapacityBytes.FindStringSubmatch(data), 1),
		ConfigurationFreeSpace:   toFloat64(reConfFreeSpaceBytes.FindStringSubmatch(data), 1),
	}
}

func mustNewConstMetricIfANumber(ch chan<- prometheus.Metric, desc *prometheus.Desc, valueType prometheus.ValueType, value float64, labelValues ...string)  { 
	if !math.IsNaN(value) {
		ch<-prometheus.MustNewConstMetric(desc , valueType, value, labelValues ...)
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

	mustNewConstMetricIfANumber(ch,p.data.certificateLast, prometheus.GaugeValue, s.CertificateLastFail, "fail")
	mustNewConstMetricIfANumber(ch,p.data.certificateLast, prometheus.GaugeValue, s.CertificateLastForcible, "forcible")
	mustNewConstMetricIfANumber(ch,p.data.certificateLast, prometheus.GaugeValue, s.CertificateLastSuccess, "success")
	mustNewConstMetricIfANumber(ch,p.data.certificateLastBytes, prometheus.GaugeValue, s.CertificateLastBytes)
	mustNewConstMetricIfANumber(ch,p.data.certificateOverflowTotal, prometheus.CounterValue, s.CertificateOverflowTotal)
	mustNewConstMetricIfANumber(ch,p.data.sharedDictionaryCapacity, prometheus.GaugeValue, s.CertificateCapacity, "certificate")
	mustNewConstMetricIfANumber(ch,p.data.sharedDictionaryCapacity, prometheus.GaugeValue, s.ConfigurationCapacity, "configuration")
	mustNewConstMetricIfANumber(ch,p.data.sharedDictionaryFree, prometheus.GaugeValue, s.CertificateFreeSpace, "certificate")
	mustNewConstMetricIfANumber(ch,p.data.sharedDictionaryFree, prometheus.GaugeValue, s.ConfigurationFreeSpace, "configuration")
}
