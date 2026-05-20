// Package portscan shells out to nmap (the right tool — don't reinvent),
// parses its XML output, and returns a structured view that downstream
// scanners can iterate over.
package portscan

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/chud-lori/ngehe/internal/finding"
)

// Service is one open port with whatever service info nmap could derive.
type Service struct {
	Host     string
	Port     int
	Proto    string // tcp / udp
	Service  string // ssh, http, smb, ldap, ...
	Product  string // OpenSSH, vsftpd, ...
	Version  string
	OSType   string
	Banner   string
}

type Result struct {
	Target   string
	Services []Service
	Findings []finding.Finding
}

// xml types matching nmap's -oX format (subset).
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	OSType  string `xml:"ostype,attr"`
	Banner  string `xml:"banner,attr"`
}

// Profile is a short alias for an nmap invocation.
type Profile string

const (
	ProfileQuick   Profile = "quick"   // -sV --top-ports 100
	ProfileFull    Profile = "full"    // -sV -p-
	ProfileService Profile = "service" // -sV -sC -p- (slow, thorough)
)

// Run shells out to nmap and returns parsed services.
func Run(target string, profile Profile, extraArgs []string) (*Result, error) {
	if _, err := exec.LookPath("nmap"); err != nil {
		return nil, fmt.Errorf("nmap not on PATH: %w (install nmap to use ngehe box)", err)
	}
	args := []string{"-T4", "-Pn", "--open", "-sV", "-oX", "-"}
	switch profile {
	case ProfileFull:
		args = append(args, "-p-")
	case ProfileService:
		args = append(args, "-sC", "-p-")
	default:
		args = append(args, "--top-ports", "100")
	}
	args = append(args, extraArgs...)
	args = append(args, target)

	fmt.Fprintf(os.Stderr, "running: nmap %s\n", strings.Join(args, " "))
	cmd := exec.Command("nmap", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nmap failed: %w", err)
	}

	var run nmapRun
	if err := xml.Unmarshal(out, &run); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}

	res := &Result{Target: target}
	for _, h := range run.Hosts {
		host := target
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				host = a.Addr
				break
			}
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			svc := Service{
				Host:    host,
				Port:    p.PortID,
				Proto:   p.Protocol,
				Service: p.Service.Name,
				Product: p.Service.Product,
				Version: p.Service.Version,
				OSType:  p.Service.OSType,
				Banner:  p.Service.Banner,
			}
			res.Services = append(res.Services, svc)
			res.Findings = append(res.Findings, finding.Finding{
				Rule:     "port-open",
				Severity: finding.SevInfo,
				Method:   strings.ToUpper(svc.Proto),
				URL:      fmt.Sprintf("%s://%s:%d", svc.Service, host, p.PortID),
				Path:     "/",
				Evidence: serviceEvidence(svc),
				Why:      fmt.Sprintf("nmap detected %s/%s open running %s", svc.Proto, svc.Service, productString(svc)),
			})
		}
	}
	return res, nil
}

func serviceEvidence(s Service) string {
	parts := []string{fmt.Sprintf("%s/%d", s.Proto, s.Port)}
	if s.Service != "" {
		parts = append(parts, s.Service)
	}
	if s.Product != "" {
		parts = append(parts, s.Product)
	}
	if s.Version != "" {
		parts = append(parts, s.Version)
	}
	return strings.Join(parts, " ")
}

func productString(s Service) string {
	if s.Product == "" && s.Version == "" {
		return s.Service
	}
	return strings.TrimSpace(s.Product + " " + s.Version)
}
