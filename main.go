package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/letsencrypt-cpanel/cpanelgo/cpanel"
	"golang.org/x/crypto/acme"

	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/soap"
)

var (
	certExpiry  = 365 * 12 * time.Hour
	certBundle  = true
	certManual  = false
	certDNS     = true
	certKeypath string

	vmuser, vmpass, cphost, cpuser, cppass string
)

func main() {

	flag.StringVar(&vmuser, "wu", "", "VMware username")
	flag.StringVar(&vmpass, "wp", "", "VMware password")

	flag.StringVar(&cphost, "cd", "", "cPanel hostname")
	flag.StringVar(&cpuser, "cu", "", "cPanel username")
	flag.StringVar(&cppass, "cp", "", "cPanel password")

	init := flag.NewFlagSet("init", flag.ExitOnError)
	var email string
	init.StringVar(&email, "email", "", "Question that you are asking for")

	init.Usage = init.PrintDefaults
	flag.Parse()

	ctx := context.Background()

	switch flag.Arg(0) {
	case init.Name():
		init.Parse(flag.Args()[1:])
		if email == "" {
			log.Printf("Required param -email not provided")
			return
		}
		_, err := newAcmeReg(ctx, []string{"mailto:" + email})
		if err != nil {
			log.Printf("Register: %s", err)
			return
		}
		log.Printf("Done !")
		return
	}

	hostname := flag.Arg(0)
	if hostname == "" {
		log.Printf("missing hostname parameter")
		return
	}

	if user := os.Getenv("VMWARE_USER"); user != "" {
		vmuser = user
	}

	if password := os.Getenv("VMWARE_PASS"); password != "" {
		vmpass = password
	}

	if host := os.Getenv("CPANEL_HOST"); host != "" {
		cphost = host
	}

	if user := os.Getenv("CPANEL_USER"); user != "" {
		cpuser = user
	}

	if password := os.Getenv("CPANEL_PASS"); password != "" {
		cppass = password
	}

	_, err := net.LookupHost(hostname)
	if err != nil {
		log.Fatalf("Failed to resolve %s: %s", hostname, err)
	}

	// cPanel
	cp, err := cpanel.NewJsonApi(cphost, cpuser, cppass, false)
	if err != nil {
		log.Printf("Cpanel %v", err)
		return
	}

	// VMware
	u, err := soap.ParseURL("https://" + vmuser + ":" + vmpass + "@" + hostname)
	if err != nil {
		log.Printf("vim.ParseURL %s", err)
		return
	}

	c, err := vim25.NewClient(ctx, soap.NewClient(u, true))
	if err != nil {
		log.Printf("vim.Newclient %s", err)
		return
	}

	m := session.NewManager(c)
	err = m.Login(ctx, u.User)
	if err != nil {
		log.Printf("vmware::Login -> %s", err)
		return
	}

	finder := find.NewFinder(c, true)

	dc, err := finder.DefaultDatacenter(ctx)
	if err != nil {
		log.Printf("DefaultDatacenter: %s", err)
		return
	}

	host, err := finder.SetDatacenter(dc).DefaultHostSystem(ctx)
	if err != nil {
		log.Printf("DefaultHostSystem: %s", err)
		return
	}

	cfgMgr, err := host.ConfigManager().CertificateManager(ctx)
	if err != nil {
		log.Printf("CertificateManager: %s", err)
		return
	}

	mgrCrt, err := cfgMgr.CertificateInfo(ctx)
	if err != nil {
		log.Printf("CertificateManager: %s", err)
		return
	}

	if mgrCrt.SubjectName().CommonName == hostname &&
		time.Now().Before(mgrCrt.NotAfter.Add(-720*time.Hour)) {
		log.Printf("Certificate `%s` Expire `%s`.", mgrCrt.SubjectName().CommonName, mgrCrt.NotAfter)
		log.Printf("Nothing to do.")
		return
	}

	csr, err := cfgMgr.GenerateCertificateSigningRequest(ctx, false)
	if err != nil {
		log.Printf("CertificateManager: %s", err)
		return
	}

	pemBlock, _ := pem.Decode([]byte(csr))
	if err != nil {
		log.Printf("Decode: %s", err)
		return
	}

	req, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		log.Printf("ParseCertificateRequest: %s", err)
		return
	}

	// FQDN
	name, domain := req.Subject.CommonName, ""
	if name != hostname {
		log.Printf("FQDN: %s does not miss match!", name)
		return
	}

	domains, err := cp.DomainsData()
	if err != nil {
		log.Printf("cpanel::Domains %s", err)
		return
	}

	for _, zone := range domains.DomainList() {
		if strings.HasSuffix(name, zone) {
			domain = zone
			goto DomainFound
		}
	}
	log.Printf("Unable to find parent of %s in %s", name, domains.DomainList())
	return
DomainFound:

	actx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	client, err := newAcmeClient(actx)
	if err != nil {
		log.Printf("acme::New -> %s", err)
		return
	}

	z, err := client.Authorize(actx, name)
	if err != nil {
		log.Printf("Authorize %s", err)
		return
	}

	var chal *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == "dns-01" {
			chal = c
			break
		}
	}
	auth, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		log.Printf("DNS01ChallengeRecord %s ", err)
		return
	}
	log.Printf("DNS Record %s", auth)

	f, err := cp.FetchZone(domain, "TXT")
	if err != nil {
		log.Printf("FetchZoneRecords %s", err)
		return
	}

	// Find record by name
	rname := "_acme-challenge." + name + "."
	for _, record := range f.Data[0].Records {
		if record.Name == rname {
			err = cp.EditZoneTextRecord(record.Line, domain, auth, "1")
			if err != nil {
				log.Printf("EditZoneTextRecord %s", err)
				return
			}
			goto acceptChallenge
		}
	}

	err = cp.AddZoneTextRecord(domain, rname, auth, "1")
	if err != nil {
		log.Printf("EditZoneTextRecord %s", err)
		return
	}

acceptChallenge:
	if _, err := client.Accept(actx, chal); err != nil {
		log.Printf("accept challenge: %v", err)
		return
	}

	_, err = client.WaitAuthorization(actx, z.URI)
	if err != nil {
		log.Printf("WaitAuthorization: %s", err)
		return
	}

	cert, _, err := client.CreateCert(actx, pemBlock.Bytes, certExpiry, certBundle)
	if err != nil {
		log.Printf("CreateCert: %v", err)
		return
	}

	var pemcert []byte
	//	var certificate string
	var caCert string
	for idx, b := range cert {
		b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		if idx == 1 {
			caCert = string(b)
		}
		pemcert = append(pemcert, b...)
		pemcert = append(pemcert, []byte("\n")...)
	}

	// VMware
	err = cfgMgr.ReplaceCACertificatesAndCRLs(ctx, []string{caCert}, nil)
	if err != nil {
		log.Fatalf("ReplaceCACertificatesAndCRLs: %v", err)
	}

	err = cfgMgr.InstallServerCertificate(ctx, string(pemcert))
	if err != nil {
		log.Fatalf("InstallServerCertificate: %v", err)
	}

}
