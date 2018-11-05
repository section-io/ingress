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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEqualConfiguration(t *testing.T) {
	ap, _ := filepath.Abs("../../test/manifests/configuration-a.json")
	a, err := readJSON(ap)
	if err != nil {
		t.Errorf("unexpected error reading JSON file: %v", err)
	}

	bp, _ := filepath.Abs("../../test/manifests/configuration-b.json")
	b, err := readJSON(bp)
	if err != nil {
		t.Errorf("unexpected error reading JSON file: %v", err)
	}

	cp, _ := filepath.Abs("../../test/manifests/configuration-c.json")
	c, err := readJSON(cp)
	if err != nil {
		t.Errorf("unexpected error reading JSON file: %v", err)
	}

	if !a.Equal(b) {
		t.Errorf("expected equal configurations (configuration-a.json and configuration-b.json)")
	}

	if !b.Equal(a) {
		t.Errorf("expected equal configurations (configuration-b.json and configuration-a.json)")
	}

	if a.Equal(c) {
		t.Errorf("expected equal configurations (configuration-a.json and configuration-c.json)")
	}
}

func TestNotEqualConfiguration(t *testing.T) {
	ap, _ := filepath.Abs("../../test/manifests/configuration-a.json")
	a, err := readJSON(ap)
	if err != nil {
		t.Errorf("unexpected error reading JSON file: %v", err)
	}

	b, err := readJSON(ap)
	if err != nil {
		t.Errorf("unexpected error reading JSON file: %v", err)
	}
	delete(b.Servers[0].TLSCertificateHostnameMap, "tlshost1")
	if a.Equal(b) {
		t.Errorf("expected not equal configurations (missing TLSCertificateHostnameMap entry)")
	}

	b, err = readJSON(ap)
	if err != nil {
		t.Errorf("unexpected error reading JSON file: %v", err)
	}
	b.Servers[0].TLSCertificateHostnameMap["tlshost3"] = PemCertificate{
		FileName: "certpath3",
		Checksum: "checksum3",
	}
	if a.Equal(b) {
		t.Errorf("expected not equal configurations (extra TLSCertificateHostnameMap entry)")
	}

	b, err = readJSON(ap)
	if err != nil {
		t.Errorf("unexpected error reading JSON file: %v", err)
	}
	delete(b.Servers[0].TLSCertificateHostnameMap, "tlshost1")
	b.Servers[0].TLSCertificateHostnameMap["tlshost3"] = PemCertificate{
		FileName: "certpath3",
		Checksum: "checksum3",
	}
	if a.Equal(b) {
		t.Errorf("expected not equal configurations (replace TLSCertificateHostnameMap entry)")
	}

	b, err = readJSON(ap)
	if err != nil {
		t.Errorf("unexpected error reading JSON file: %v", err)
	}
	pem := b.Servers[0].TLSCertificateHostnameMap["tlshost1"]
	pem.FileName = "NOTcertpath1"
	b.Servers[0].TLSCertificateHostnameMap["tlshost1"] = pem
	if a.Equal(b) {
		t.Errorf("expected not equal configurations (TLSCertificateHostnameMap FileName change)")
	}

	b, err = readJSON(ap)
	if err != nil {
		t.Errorf("unexpected error reading JSON file: %v", err)
	}
	pem = b.Servers[0].TLSCertificateHostnameMap["tlshost1"]
	pem.Checksum = "NOTchecksum1"
	b.Servers[0].TLSCertificateHostnameMap["tlshost1"] = pem
	if a.Equal(b) {
		t.Errorf("expected not equal configurations (TLSCertificateHostnameMap Checksum change)")
	}
}

func readJSON(p string) (*Configuration, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}

	var c Configuration

	d := json.NewDecoder(f)
	err = d.Decode(&c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}
