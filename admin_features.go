package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

func logAdminEvent(level, message string) {
	_, _ = db.Exec("INSERT INTO admin_logs (level, message) VALUES (?, ?)", level, message)
}

func toJSONString(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func getAdminDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var totalPolls int
	var activePolls int
	var pendingPolls int
	var totalVotes int
	var totalIncidents int
	var activeRules int

	_ = db.QueryRow("SELECT COUNT(*) FROM polls").Scan(&totalPolls)
	_ = db.QueryRow("SELECT COUNT(*) FROM polls WHERE active = 1").Scan(&activePolls)
	_ = db.QueryRow("SELECT COUNT(*) FROM polls WHERE status = 'pending'").Scan(&pendingPolls)
	_ = db.QueryRow("SELECT COUNT(*) FROM votes").Scan(&totalVotes)
	_ = db.QueryRow("SELECT COUNT(*) FROM fraud_alerts").Scan(&totalIncidents)
	_ = db.QueryRow("SELECT COUNT(*) FROM fraud_rules WHERE active = 1").Scan(&activeRules)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data: map[string]interface{}{
			"totalPolls":     totalPolls,
			"activePolls":    activePolls,
			"pendingPolls":   pendingPolls,
			"totalVotes":     totalVotes,
			"totalIncidents": totalIncidents,
			"activeRules":    activeRules,
		},
	})
}

func getIncidents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query(`
		SELECT fa.id, fa.fingerprint, fa.poll_id, COALESCE(p.title, ''), fa.reason,
		       COALESCE(fa.country_code, ''), COALESCE(fa.country_name, ''), COALESCE(fa.ip, ''), fa.created_at
		FROM fraud_alerts fa
		LEFT JOIN polls p ON fa.poll_id = p.id
		ORDER BY fa.created_at DESC
		LIMIT 100
	`)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка загрузки инцидентов",
		})
		return
	}
	defer rows.Close()

	var incidents []map[string]interface{}
	for rows.Next() {
		var id int
		var fingerprint string
		var pollID int
		var pollTitle string
		var reason string
		var countryCode string
		var countryName string
		var ip string
		var createdAt string

		if err := rows.Scan(&id, &fingerprint, &pollID, &pollTitle, &reason, &countryCode, &countryName, &ip, &createdAt); err != nil {
			continue
		}

		incidents = append(incidents, map[string]interface{}{
			"id":          id,
			"fingerprint": fingerprint,
			"pollId":      pollID,
			"pollTitle":   pollTitle,
			"reason":      reason,
			"countryCode": countryCode,
			"countryName": countryName,
			"ip":          ip,
			"createdAt":   createdAt,
		})
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    incidents,
	})
}

func getRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query(`
		SELECT id, name, rule_type, COALESCE(target_value, ''), COALESCE(threshold, 0),
		       COALESCE(window_minutes, 0), COALESCE(poll_id, 0), action, active, created_at
		FROM fraud_rules
		ORDER BY created_at DESC
	`)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка загрузки правил",
		})
		return
	}
	defer rows.Close()

	var rules []map[string]interface{}
	for rows.Next() {
		var id int
		var name, ruleType, targetValue, action, createdAt string
		var threshold, windowMinutes, pollID int
		var active bool

		if err := rows.Scan(&id, &name, &ruleType, &targetValue, &threshold, &windowMinutes, &pollID, &action, &active, &createdAt); err != nil {
			continue
		}

		rules = append(rules, map[string]interface{}{
			"id":            id,
			"name":          name,
			"ruleType":      ruleType,
			"targetValue":   targetValue,
			"threshold":     threshold,
			"windowMinutes": windowMinutes,
			"pollId":        pollID,
			"action":        action,
			"active":        active,
			"createdAt":     createdAt,
		})
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    rules,
	})
}

func createRule(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Name          string `json:"name"`
		RuleType      string `json:"ruleType"`
		TargetValue   string `json:"targetValue"`
		Threshold     int    `json:"threshold"`
		WindowMinutes int    `json:"windowMinutes"`
		PollID        int    `json:"pollId"`
		Action        string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Неверный формат запроса",
		})
		return
	}

	if req.Name == "" {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Введите название правила",
		})
		return
	}

	if req.RuleType == "" {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Выберите тип правила",
		})
		return
	}

	if req.Action == "" {
		req.Action = "block"
	}

	_, err := db.Exec(`
		INSERT INTO fraud_rules (name, rule_type, target_value, threshold, window_minutes, poll_id, action, active)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1)
	`, req.Name, req.RuleType, req.TargetValue, req.Threshold, req.WindowMinutes, req.PollID, req.Action)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка создания правила",
		})
		return
	}

	logAdminEvent("info", "Создано правило: "+req.Name)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Правило успешно создано",
	})
}

func toggleRule(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	idStr := vars["id"]

	ruleID, err := strconv.Atoi(idStr)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Некорректный ID правила",
		})
		return
	}

	var current bool
	err = db.QueryRow("SELECT active FROM fraud_rules WHERE id = ?", ruleID).Scan(&current)
	if err == sql.ErrNoRows {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Правило не найдено",
		})
		return
	}
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка получения правила",
		})
		return
	}

	_, err = db.Exec("UPDATE fraud_rules SET active = ? WHERE id = ?", !current, ruleID)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка обновления правила",
		})
		return
	}

	logAdminEvent("warning", "Изменен статус правила ID="+idStr)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Статус правила обновлен",
	})
}

func deleteRule(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	idStr := vars["id"]

	ruleID, err := strconv.Atoi(idStr)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Некорректный ID правила",
		})
		return
	}

	res, err := db.Exec("DELETE FROM fraud_rules WHERE id = ?", ruleID)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка удаления правила",
		})
		return
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Правило не найдено",
		})
		return
	}

	logAdminEvent("warning", "Удалено правило ID="+idStr)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Правило удалено",
	})
}

func getAnalytics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var totalVotes int
	var blockedVotes int
	var uniquePolls int

	_ = db.QueryRow("SELECT COUNT(*) FROM votes").Scan(&totalVotes)
	_ = db.QueryRow("SELECT COUNT(*) FROM fraud_alerts").Scan(&blockedVotes)
	_ = db.QueryRow("SELECT COUNT(DISTINCT poll_id) FROM votes").Scan(&uniquePolls)

	rows, err := db.Query(`
		SELECT p.title, COUNT(v.id) as vote_count
		FROM polls p
		LEFT JOIN votes v ON p.id = v.poll_id
		GROUP BY p.id
		ORDER BY vote_count DESC, p.created_at DESC
		LIMIT 10
	`)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка загрузки аналитики",
		})
		return
	}
	defer rows.Close()

	var topPolls []map[string]interface{}
	for rows.Next() {
		var title string
		var voteCount int

		if err := rows.Scan(&title, &voteCount); err != nil {
			continue
		}

		topPolls = append(topPolls, map[string]interface{}{
			"title":     title,
			"voteCount": voteCount,
		})
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data: map[string]interface{}{
			"totalVotes":   totalVotes,
			"blockedVotes": blockedVotes,
			"uniquePolls":  uniquePolls,
			"topPolls":     topPolls,
		},
	})
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query(`
		SELECT id, level, message, created_at
		FROM admin_logs
		ORDER BY created_at DESC
		LIMIT 200
	`)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка загрузки логов",
		})
		return
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id int
		var level, message, createdAt string

		if err := rows.Scan(&id, &level, &message, &createdAt); err != nil {
			continue
		}

		logs = append(logs, map[string]interface{}{
			"id":        id,
			"level":     level,
			"message":   message,
			"createdAt": createdAt,
		})
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    logs,
	})
}
