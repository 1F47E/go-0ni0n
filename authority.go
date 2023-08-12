package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const URL_AUTH_DIRS = "https://raw.githubusercontent.com/torproject/tor/main/src/app/config/auth_dirs.inc"
const PATH_CONSENSUS = "/tor/status-vote/current/consensus"
const TIMEOUT = 10 * time.Second

type Authority struct {
	Name        string
	Orport      string
	Port        string
	Bridge      bool
	V3ident     string
	IPv6        string
	IPv4        string
	Fingerprint string
}

func (a Authority) String() string {
	// return fmt.Sprintf("Name: %s\n Orport: %s\n Bridge: %t\n V3ident: %s\n IPv6: %s\n IPv4: %s\n Fingerprint: %s\n",
	// 	a.Name, a.Orport, a.Bridge, a.V3ident, a.IPv6, a.IPv4, a.Fingerprint)
	return fmt.Sprintf("Name: %s\nEndpoint: %s\n ",
		a.Name, a.URL())
}

func (a Authority) Endpoint() string {
	ip := ""
	if a.IPv4 != "" {
		ip = a.IPv4
	} else {
		ip = a.IPv6
	}
	return fmt.Sprintf("%s:%s", ip, a.Port)
}

func (a Authority) URL() string {
	if a.Port == "443" {
		return fmt.Sprintf("https://%s%s", a.IPv4, PATH_CONSENSUS)
	} else if a.Port == "80" {
		return fmt.Sprintf("http://%s%s", a.IPv4, PATH_CONSENSUS)
	} else {
		return fmt.Sprintf("http://%s:%s%s", a.IPv4, a.Port, PATH_CONSENSUS)
	}
}

func Parse() ([]Authority, error) {
	data, err := getAuthorities()
	if err != nil {
		return nil, fmt.Errorf("Error getting authorities: %s", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("No data")
	}
	dirs := parseAuthorities(data)
	fmt.Printf("Got auth dir data: %d bytes\n", len(data))

	return dirs, nil
}

func getAuthorities() ([]byte, error) {
	client := &http.Client{
		Timeout: TIMEOUT,
	}
	req, err := http.NewRequest("GET", URL_AUTH_DIRS, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating request: %s", err)
	}
	req.Header.Set("User-Agent", "Tor-Directory-Scraper/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error sending request: %s", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response: %s", err)
	}
	return data, nil
}

func parseAuthorities(data []byte) []Authority {
	// read from file
	// file, err := os.Open("auth_dirs.txt")
	// if err != nil {
	// }
	// defer file.Close()

	// var lines []string
	// scanner := bufio.NewScanner(file)
	// for scanner.Scan() {
	// 	lines = append(lines, scanner.Text())
	// }

	lines := strings.Split(string(data), "\n")

	var authorities []Authority
	groups := make(map[int][]string)
	idx := 0
	for _, line := range lines {
		// detect new group
		if strings.Contains(line, "orport") {
			idx++
		}
		groups[idx] = append(groups[idx], line)
	}
	// fmt.Printf("Found %d groups\n", len(groups))
	for _, group := range groups {
		authorities = append(authorities, parseGroup(group))
		// fmt.Printf("Group %d : %s\n", k, group)
	}

	return authorities
}

func parseGroup(lines []string) Authority {
	// fmt.Printf("BLOCK:\n%s\n", lines)
	// fmt.Println()

	var auth Authority

	for _, line := range lines {
		// Parse the first line
		if strings.Contains(line, "orport=") {
			parts := strings.Fields(strings.Trim(line, "\","))
			auth.Name = parts[0]

			// orport
			auth.Orport = strings.Replace(parts[1], "orport=", "", -1)
			auth.Bridge = strings.Contains(line, "bridge")
			continue
		}

		// // Parse the second line
		if strings.Contains(line, "v3ident") {
			v3ident := strings.Replace(line, "v3ident=", "", -1)
			v3ident = strings.Replace(v3ident, "\"", "", -1)
			v3ident = strings.TrimSpace(v3ident)
			auth.V3ident = v3ident
			continue
		} else {
			// custom case
			// "Serge orport=9001 bridge "
			// "66.111.2.131:9030 BA44 A889 E64B 93FA A2B1 14E0 2C2A 279A 8555 C533",
			parts := strings.Split(strings.Replace(line, "\"", "", -1), ":")
			if len(parts) > 1 {
				ip := strings.TrimSpace(parts[0])
				auth.IPv4 = ip
				parts = strings.Split(parts[1], " ")
				auth.Port = parts[0]
				// fmt.Printf("IPv4: %s, Orport: %s\n", auth.IPv4, auth.Orport)
				fingerprint := strings.Join(parts[1:], "")
				fingerprint = strings.ReplaceAll(fingerprint, ",", "")
				fingerprint = strings.ReplaceAll(fingerprint, " ", "")
				// fmt.Printf("Fingerprint: %s\n", fingerprint)
				auth.Fingerprint = fingerprint
			}
			continue
		}

	}
	return auth
}
