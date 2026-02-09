package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

// FleetDM webhook payload structures
type WebhookPayload struct {
	Timestamp string   `json:"timestamp"`
	Details   []Detail `json:"details"`
}

type Detail struct {
	Action         string            `json:"action"`
	CalendarTime   string            `json:"calendarTime"`
	Columns        map[string]string `json:"columns"`
	Counter        int               `json:"counter"`
	Decorations    Decorations       `json:"decorations"`
	Epoch          int               `json:"epoch"`
	HostIdentifier string            `json:"hostIdentifier"`
	Name           string            `json:"name"`
	Numerics       bool              `json:"numerics"`
	QueryID        int               `json:"query_id"`
	UnixTime       int64             `json:"unixTime"`
}

type Decorations struct {
	HostUUID string `json:"host_uuid"`
	Hostname string `json:"hostname"`
}

// ntfy notification structure
type NtfyNotification struct {
	Topic    string   `json:"topic"`
	Title    string   `json:"title"`
	Message  string   `json:"message"`
	Priority int      `json:"priority"`
	Tags     []string `json:"tags"`
}

// Config holds application configuration
type Config struct {
	ListenAddr string
	NtfyURL    string
	NtfyTopic  string
}

func loadConfig() Config {
	return Config{
		ListenAddr: getEnv("LISTEN_ADDR", ":8080"),
		NtfyURL:    getEnv("NTFY_URL", "https://ntfy.sh"),
		NtfyTopic:  getEnv("NTFY_TOPIC", "fleet-alerts"),
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// parseQueryName extracts detection category and name from the full query name
// e.g., "pack/Global/[detection/persistence] Unexpected Device Linux" ->
//
//	category: "persistence", name: "Unexpected Device Linux"
func parseQueryName(fullName string) (category, name string) {
	// Try to extract [detection/category] pattern
	re := regexp.MustCompile(`\[([^\]]+)\]\s*(.+)$`)
	matches := re.FindStringSubmatch(fullName)
	if len(matches) == 3 {
		category = matches[1]
		name = matches[2]
		return
	}

	// Fallback: use the last part after the final /
	parts := strings.Split(fullName, "/")
	name = parts[len(parts)-1]
	category = "alert"
	return
}

// getPriority determines ntfy priority based on detection category
func getPriority(category string) int {
	category = strings.ToLower(category)

	switch {
	case strings.Contains(category, "c2"):
		return 5 // urgent
	case strings.Contains(category, "execution"):
		return 5 // urgent
	case strings.Contains(category, "credential"):
		return 4 // high
	case strings.Contains(category, "persistence"):
		return 4 // high
	case strings.Contains(category, "privilege"):
		return 4 // high
	case strings.Contains(category, "defense"):
		return 4 // high
	case strings.Contains(category, "exfil"):
		return 5 // urgent
	case strings.Contains(category, "lateral"):
		return 4 // high
	default:
		return 3 // default
	}
}

// getTags returns ntfy tags/emojis based on category
func getTags(category string) []string {
	category = strings.ToLower(category)

	tags := []string{"computer"}

	switch {
	case strings.Contains(category, "c2"):
		tags = append(tags, "warning", "satellite")
	case strings.Contains(category, "execution"):
		tags = append(tags, "warning", "zap")
	case strings.Contains(category, "persistence"):
		tags = append(tags, "warning", "anchor")
	case strings.Contains(category, "credential"):
		tags = append(tags, "warning", "key")
	case strings.Contains(category, "privilege"):
		tags = append(tags, "warning", "crown")
	case strings.Contains(category, "exfil"):
		tags = append(tags, "rotating_light", "outbox_tray")
	case strings.Contains(category, "network"):
		tags = append(tags, "globe_with_meridians")
	default:
		tags = append(tags, "mag")
	}

	return tags
}

// formatColumns formats the columns map into a readable string
func formatColumns(columns map[string]string) string {
	if len(columns) == 0 {
		return ""
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(columns))
	for k := range columns {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Prioritize important fields first
	priorityFields := []string{"path", "name", "cmdline", "command", "cmd", "parent_path", "parent_cmd", "user", "uid", "gid", "local_address", "local_port", "remote_address", "remote_port", "sha256", "state"}

	var sb strings.Builder
	seen := make(map[string]bool)

	// First, output priority fields that exist
	for _, key := range priorityFields {
		if val, exists := columns[key]; exists && val != "" && val != "0" {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", key, val))
			seen[key] = true
		}
	}

	// Then output remaining fields
	for _, key := range keys {
		if seen[key] {
			continue
		}
		val := columns[key]
		// Skip empty or zero values for less noise
		if val == "" || val == "0" {
			continue
		}
		// Skip some noisy fields
		if key == "exception_key" || key == "numerics" {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s: %s\n", key, val))
	}

	return sb.String()
}

// groupDetailsByAction groups details by their action (added/removed)
func groupDetailsByAction(details []Detail) map[string][]Detail {
	grouped := make(map[string][]Detail)
	for _, d := range details {
		grouped[d.Action] = append(grouped[d.Action], d)
	}
	return grouped
}

// formatNotification creates an ntfy notification from FleetDM webhook payload
func formatNotification(payload WebhookPayload, config Config) *NtfyNotification {
	if len(payload.Details) == 0 {
		return nil
	}

	// Get info from first detail (they should all be from same query)
	first := payload.Details[0]
	hostname := first.Decorations.Hostname
	if hostname == "" {
		hostname = first.HostIdentifier
	}

	category, queryName := parseQueryName(first.Name)

	// Build title
	title := fmt.Sprintf("%s - %s", queryName, hostname)

	// Build message body
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("Host: %s\n", hostname))
	msg.WriteString(fmt.Sprintf("Detection: %s\n", category))
	msg.WriteString(fmt.Sprintf("Time: %s\n", first.CalendarTime))
	msg.WriteString("\n")

	// Group by action for cleaner output
	grouped := groupDetailsByAction(payload.Details)

	// Order: removed first, then added
	for _, action := range []string{"removed", "added"} {
		details, exists := grouped[action]
		if !exists {
			continue
		}

		actionSymbol := "−"
		if action == "added" {
			actionSymbol = "+"
		}

		msg.WriteString(fmt.Sprintf("[%s %s]\n", actionSymbol, action))

		for _, detail := range details {
			// Try to get a meaningful identifier from columns
			identifier := getIdentifier(detail.Columns)
			if identifier != "" {
				msg.WriteString(fmt.Sprintf("• %s\n", identifier))
			}
			msg.WriteString(formatColumns(detail.Columns))
			msg.WriteString("\n")
		}
	}

	return &NtfyNotification{
		Topic:    config.NtfyTopic,
		Title:    title,
		Message:  strings.TrimSpace(msg.String()),
		Priority: getPriority(category),
		Tags:     getTags(category),
	}
}

// getIdentifier tries to extract a meaningful identifier from columns
func getIdentifier(columns map[string]string) string {
	// Try various common identifier fields
	identifierFields := []string{"path", "name", "filename", "cmdline", "command"}

	for _, field := range identifierFields {
		if val, exists := columns[field]; exists && val != "" {
			return val
		}
	}
	return ""
}

// sendToNtfy sends a notification to the ntfy server
func sendToNtfy(notification *NtfyNotification, config Config) error {
	jsonData, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to marshal notification: %w", err)
	}

	resp, err := http.Post(config.NtfyURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send to ntfy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ntfy returned error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// webhookHandler handles incoming FleetDM webhook requests
func webhookHandler(config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading request body: %v", err)
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var payload WebhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			log.Printf("Error parsing JSON: %v", err)
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		notification := formatNotification(payload, config)
		if notification == nil {
			log.Printf("No details in webhook payload")
			w.WriteHeader(http.StatusOK)
			return
		}

		if err := sendToNtfy(notification, config); err != nil {
			log.Printf("Error sending to ntfy: %v", err)
			http.Error(w, "Failed to send notification", http.StatusInternalServerError)
			return
		}

		log.Printf("Notification sent: %s", notification.Title)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}
}

func main() {
	config := loadConfig()

	log.Printf("Starting fleet-ntfy-webhook server")
	log.Printf("  Listen address: %s", config.ListenAddr)
	log.Printf("  ntfy URL: %s", config.NtfyURL)
	log.Printf("  ntfy topic: %s", config.NtfyTopic)

	http.HandleFunc("/webhook", webhookHandler(config))

	log.Printf("Server listening on %s", config.ListenAddr)
	if err := http.ListenAndServe(config.ListenAddr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
