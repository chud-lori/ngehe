// Package ftp probes FTP for anonymous login, banner, and writable dirs.
package ftp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/chud-lori/ngehe/internal/finding"
)

func Scan(host string, port int) []finding.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(conn)
	banner, _ := readResp(br)

	var out []finding.Finding
	if banner != "" {
		out = append(out, finding.Finding{
			Rule: "ftp-banner", Severity: finding.SevInfo,
			Method: "TCP", URL: "ftp://" + addr, Path: "/",
			Evidence: banner,
			Why:      "FTP banner exposed; use for version-based CVE lookup",
		})
	}

	// Try anonymous login.
	if _, err := conn.Write([]byte("USER anonymous\r\n")); err != nil {
		return out
	}
	userResp, _ := readResp(br)
	if _, err := conn.Write([]byte("PASS ngehe@example.com\r\n")); err != nil {
		return out
	}
	passResp, _ := readResp(br)
	if !strings.HasPrefix(passResp, "230") {
		out = append(out, finding.Finding{
			Rule: "ftp-anonymous-denied", Severity: finding.SevInfo,
			Method: "TCP", URL: "ftp://" + addr, Path: "/",
			Evidence: userResp + " | " + passResp,
			Why:      "anonymous login refused (expected for hardened servers)",
		})
		return out
	}

	out = append(out, finding.Finding{
		Rule: "ftp-anonymous-allowed", Severity: finding.SevHigh,
		Method: "TCP", URL: "ftp://" + addr, Path: "/",
		Evidence: passResp,
		Why:      "FTP server accepts anonymous login — any file the user can read is world-readable",
	})

	// Try a PASV + LIST to capture top-level listing.
	if listing := listRoot(conn, br); listing != "" {
		out = append(out, finding.Finding{
			Rule: "ftp-anonymous-listing", Severity: finding.SevHigh,
			Method: "TCP", URL: "ftp://" + addr, Path: "/",
			Evidence: truncate(listing, 400),
			Why:      "anonymous FTP exposes file listing",
		})
	}
	return out
}

func readResp(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// listRoot does an FTP PASV then LIST and reads the data connection briefly.
func listRoot(ctrl net.Conn, br *bufio.Reader) string {
	if _, err := ctrl.Write([]byte("TYPE I\r\nPASV\r\n")); err != nil {
		return ""
	}
	_, _ = readResp(br) // TYPE reply
	pasv, err := readResp(br)
	if err != nil || !strings.HasPrefix(pasv, "227") {
		return ""
	}
	dataAddr := parsePASV(pasv)
	if dataAddr == "" {
		return ""
	}
	data, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		return ""
	}
	defer data.Close()
	_ = data.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := ctrl.Write([]byte("LIST\r\n")); err != nil {
		return ""
	}
	_, _ = readResp(br)
	buf := make([]byte, 8*1024)
	n, _ := data.Read(buf)
	return string(buf[:n])
}

// PASV reply looks like "227 Entering Passive Mode (10,10,10,10,123,45)."
func parsePASV(line string) string {
	open := strings.Index(line, "(")
	close := strings.Index(line, ")")
	if open < 0 || close < 0 || close <= open {
		return ""
	}
	parts := strings.Split(line[open+1:close], ",")
	if len(parts) != 6 {
		return ""
	}
	ip := strings.Join(parts[:4], ".")
	p1, p2 := 0, 0
	fmt.Sscanf(parts[4], "%d", &p1)
	fmt.Sscanf(parts[5], "%d", &p2)
	return fmt.Sprintf("%s:%d", ip, p1*256+p2)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
