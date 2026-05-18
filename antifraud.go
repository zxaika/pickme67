package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type AntiFraudSystem struct {
	httpClient *http.Client
	publicIP   string
}

type IpApiIsResponse struct {
	IP  string `json:"ip"`
	VPN struct {
		IsVPN bool   `json:"is_vpn"`
		IsTOR bool   `json:"is_tor"`
		Name  string `json:"name"`
	} `json:"vpn"`
	Proxy struct {
		IsProxy bool   `json:"is_proxy"`
		Type    string `json:"type"`
	} `json:"proxy"`
	Company struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"company"`
	Location struct {
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
	} `json:"location"`
}

func NewAntiFraudSystem() *AntiFraudSystem {
	afs := &AntiFraudSystem{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	go afs.updatePublicIP()
	return afs
}

func (a *AntiFraudSystem) updatePublicIP() {
	resp, err := a.httpClient.Get("https://api.ipify.org?format=text")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err == nil {
		a.publicIP = string(ip)
	}
}

func (a *AntiFraudSystem) GetFingerprint(r *http.Request) string {
	ip := getRealIP(r)
	hash := md5.Sum([]byte(ip))
	return hex.EncodeToString(hash[:])
}

func getRealIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip != "" && !isLocalhost(ip) {
		return ip
	}

	ip = r.Header.Get("X-Forwarded-For")
	if ip != "" {
		ips := strings.Split(ip, ",")
		if len(ips) > 0 {
			firstIP := strings.TrimSpace(ips[0])
			if !isLocalhost(firstIP) {
				return firstIP
			}
		}
	}

	ip = r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	ip = strings.Trim(ip, "[]")

	if !isLocalhost(ip) {
		return ip
	}

	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" && !isLocalhost(cfIP) {
		return cfIP
	}
	if trueClientIP := r.Header.Get("True-Client-IP"); trueClientIP != "" && !isLocalhost(trueClientIP) {
		return trueClientIP
	}

	return ip
}

func isLocalhost(ip string) bool {
	ip = strings.Trim(ip, "[]")
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost" || ip == ""
}

func detectOS(userAgent string) string {
	ua := strings.ToLower(userAgent)

	switch {
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "iphone"), strings.Contains(ua, "ipad"), strings.Contains(ua, "ios"):
		return "iOS"
	case strings.Contains(ua, "mac os"), strings.Contains(ua, "macintosh"):
		return "macOS"
	case strings.Contains(ua, "linux"):
		return "Linux"
	default:
		return "Unknown"
	}
}

func (a *AntiFraudSystem) IsAllowed(r *http.Request, pollID int, userID *int) (bool, string) {
	ip := getRealIP(r)
	ipFingerprint := a.GetFingerprint(r)

	checkIP := ip
	if isLocalhost(ip) {
		publicIP, err := a.getPublicIP()
		if err == nil && publicIP != "" {
			checkIP = publicIP
		}
	}

	vpnInfo, err := a.checkVPNProxy(checkIP)
	if err == nil && vpnInfo != nil {
		if blocked, msg := a.checkCustomRules(r, vpnInfo, pollID, ipFingerprint); blocked {
			return false, msg
		}
	}

	return a.checkVotes(ipFingerprint, pollID, userID)
}

func (a *AntiFraudSystem) checkCustomRules(r *http.Request, vpnInfo *IpApiIsResponse, pollID int, ipFingerprint string) (bool, string) {
	rows, err := db.Query(`
		SELECT id, name, rule_type, COALESCE(target_value, ''), COALESCE(threshold, 0),
		       COALESCE(window_minutes, 0), COALESCE(poll_id, 0), action
		FROM fraud_rules
		WHERE active = 1
	`)
	if err != nil {
		return false, ""
	}
	defer rows.Close()

	userAgent := r.UserAgent()
	detectedOS := detectOS(userAgent)
	userAgentLower := strings.ToLower(userAgent)

	now := time.Now()
	currentMinutes := now.Hour()*60 + now.Minute()

	for rows.Next() {
		var id int
		var name, ruleType, targetValue, action string
		var threshold, windowMinutes, rulePollID int

		if err := rows.Scan(&id, &name, &ruleType, &targetValue, &threshold, &windowMinutes, &rulePollID, &action); err != nil {
			continue
		}

		if rulePollID > 0 && rulePollID != pollID {
			continue
		}

		switch ruleType {
		case "country_block":
			if targetValue != "" && strings.EqualFold(targetValue, vpnInfo.Location.CountryCode) && action == "block" {
				return true, fmt.Sprintf("Сработало правило \"%s\": страна %s заблокирована", name, vpnInfo.Location.Country)
			}

		case "country_allow_only":
			if targetValue != "" && !strings.EqualFold(targetValue, vpnInfo.Location.CountryCode) && action == "block" {
				return true, fmt.Sprintf("Сработало правило \"%s\": голосование разрешено только для страны %s", name, strings.ToUpper(targetValue))
			}

		case "os_block":
			if targetValue != "" && strings.EqualFold(targetValue, detectedOS) && action == "block" {
				return true, fmt.Sprintf("Сработало правило \"%s\": ОС %s заблокирована", name, detectedOS)
			}

		case "empty_user_agent_block":
			if strings.TrimSpace(userAgent) == "" && action == "block" {
				return true, fmt.Sprintf("Сработало правило \"%s\": пустой User-Agent", name)
			}

		case "user_agent_contains_block":
			if targetValue != "" && strings.Contains(userAgentLower, strings.ToLower(targetValue)) && action == "block" {
				return true, fmt.Sprintf("Сработало правило \"%s\": User-Agent содержит \"%s\"", name, targetValue)
			}

		case "ip_attempt_limit":
			if threshold <= 0 || windowMinutes <= 0 {
				continue
			}

			var count int
			err := db.QueryRow(`
				SELECT COUNT(*)
				FROM fraud_alerts
				WHERE fingerprint = ?
				  AND datetime(created_at) >= datetime('now', ?)
			`, ipFingerprint, "-"+strconv.Itoa(windowMinutes)+" minutes").Scan(&count)

			if err == nil && count >= threshold && action == "block" {
				return true, fmt.Sprintf("Сработало правило \"%s\": слишком много подозрительных попыток с одного IP", name)
			}

		case "time_block":
			if targetValue == "" || action != "block" {
				continue
			}

			parts := strings.Split(targetValue, "-")
			if len(parts) != 2 {
				continue
			}

			start, err1 := parseTimeToMinutes(parts[0])
			end, err2 := parseTimeToMinutes(parts[1])
			if err1 != nil || err2 != nil {
				continue
			}

			inBlockedRange := false

			if start <= end {
				inBlockedRange = currentMinutes >= start && currentMinutes <= end
			} else {
				inBlockedRange = currentMinutes >= start || currentMinutes <= end
			}

			if inBlockedRange {
				return true, fmt.Sprintf("Сработало правило \"%s\": голосование запрещено в это время", name)
			}
		}
	}

	return false, ""
}

func parseTimeToMinutes(value string) (int, error) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time format")
	}

	hour, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}

	minute, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, err
	}

	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("invalid time value")
	}

	return hour*60 + minute, nil
}

func (a *AntiFraudSystem) checkVPNProxy(ip string) (*IpApiIsResponse, error) {
	url := "https://api.ipapi.is?q=" + ip
	resp, err := a.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result IpApiIsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (a *AntiFraudSystem) checkVotes(ipFingerprint string, pollID int, userID *int) (bool, string) {
	var count int
	var dbErr error

	if userID != nil && *userID > 0 {
		dbErr = db.QueryRow(`
			SELECT COUNT(*) FROM votes
			WHERE poll_id = ? AND user_id = ?
		`, pollID, userID).Scan(&count)

		if dbErr == nil && count > 0 {
			return false, "Вы уже голосовали в этом опросе"
		}

		var ipCount int
		dbErr = db.QueryRow(`
			SELECT COUNT(*) FROM votes v
			WHERE v.poll_id = ? AND v.guest_id = ?
		`, pollID, ipFingerprint).Scan(&ipCount)

		if dbErr == nil && ipCount > 0 {
			return false, "С этого IP уже голосовали"
		}
	} else {
		dbErr = db.QueryRow(`
			SELECT COUNT(*) FROM votes
			WHERE poll_id = ? AND guest_id = ?
		`, pollID, ipFingerprint).Scan(&count)

		if dbErr == nil && count > 0 {
			return false, "С этого IP уже голосовали"
		}
	}

	if dbErr != nil {
		return false, "Ошибка проверки антифрода"
	}

	return true, ""
}

func (a *AntiFraudSystem) GetVoterInfo(r *http.Request) map[string]string {
	ip := getRealIP(r)

	checkIP := ip
	if isLocalhost(ip) {
		publicIP, _ := a.getPublicIP()
		if publicIP != "" {
			checkIP = publicIP
		}
	}

	vpnInfo, _ := a.checkVPNProxy(checkIP)

	info := map[string]string{
		"ip":               ip,
		"checked_ip":       checkIP,
		"ip_hash":          a.GetFingerprint(r),
		"user_agent":       r.UserAgent(),
		"os":               detectOS(r.UserAgent()),
		"remote_addr":      r.RemoteAddr,
		"server_public_ip": a.publicIP,
	}

	if vpnInfo != nil {
		info["country"] = vpnInfo.Location.Country
		info["country_code"] = vpnInfo.Location.CountryCode
		info["is_vpn"] = boolToString(vpnInfo.VPN.IsVPN)
		info["vpn_name"] = vpnInfo.VPN.Name
		info["is_tor"] = boolToString(vpnInfo.VPN.IsTOR)
		info["is_proxy"] = boolToString(vpnInfo.Proxy.IsProxy)
		info["proxy_type"] = vpnInfo.Proxy.Type
		info["company_type"] = vpnInfo.Company.Type
		info["company_name"] = vpnInfo.Company.Name
	}

	headers := []string{
		"X-Real-IP",
		"X-Forwarded-For",
		"CF-Connecting-IP",
		"True-Client-IP",
		"X-Forwarded",
		"Forwarded-For",
	}

	for _, header := range headers {
		if value := r.Header.Get(header); value != "" {
			info[strings.ToLower(header)] = value
		}
	}

	return info
}

func (a *AntiFraudSystem) getPublicIP() (string, error) {
	if a.publicIP != "" {
		return a.publicIP, nil
	}

	resp, err := a.httpClient.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	a.publicIP = string(ip)
	return a.publicIP, nil
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
