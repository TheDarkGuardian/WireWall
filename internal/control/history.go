package control

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const historyExportLimit = 10000

var ErrHistoryFilter = errors.New("geçmiş filtresi geçersiz")

type EventFilter struct {
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	Source        string    `json:"source"`
	Destination   string    `json:"destination"`
	Protocol      string    `json:"protocol"`
	Action        string    `json:"action"`
	Reason        string    `json:"reason"`
	RuleID        string    `json:"ruleId"`
	Query         string    `json:"query"`
	Port          *uint16   `json:"port"`
	PolicyVersion uint64    `json:"policyVersion"`
	Simulated     bool      `json:"simulated"`
	Limit         int       `json:"-"`
	Cursor        string    `json:"-"`
}
type NamedCount struct {
	Label string `json:"label"`
	Count uint64 `json:"count"`
}
type EventSummary struct {
	MatchedEvents   uint64       `json:"matchedEvents"`
	PassedEvents    uint64       `json:"passedEvents"`
	DroppedEvents   uint64       `json:"droppedEvents"`
	WouldDropEvents uint64       `json:"wouldDropEvents"`
	SampleBytes     uint64       `json:"sampleBytes"`
	UniqueSources   uint64       `json:"uniqueSources"`
	Protocols       []NamedCount `json:"protocols"`
	Reasons         []NamedCount `json:"reasons"`
	Sources         []NamedCount `json:"sources"`
	Rules           []NamedCount `json:"rules"`
	Timeline        []NamedCount `json:"timeline"`
}
type EventHistory struct {
	Items           []Event      `json:"items"`
	Summary         EventSummary `json:"summary"`
	HasMore         bool         `json:"hasMore"`
	NextCursor      string       `json:"nextCursor,omitempty"`
	From            time.Time    `json:"from"`
	To              time.Time    `json:"to"`
	GeneratedAt     time.Time    `json:"generatedAt"`
	Simulated       bool         `json:"simulated"`
	Sampled         bool         `json:"sampled"`
	RetentionDays   int          `json:"retentionDays"`
	RecordLimit     int          `json:"recordLimit"`
	RetainedEvents  uint64       `json:"retainedEvents"`
	OldestAvailable string       `json:"oldestAvailable,omitempty"`
	ExportLimit     int          `json:"exportLimit"`
}
type eventCursor struct {
	Timestamp string    `json:"timestamp"`
	ID        string    `json:"id"`
	Anchor    time.Time `json:"anchor"`
	Filter    string    `json:"filter"`
}

func parseEventFilter(values url.Values, simulated bool, maximum int) (EventFilter, error) {
	q := EventFilter{Simulated: simulated, Limit: 100, Source: values.Get("source"), Destination: values.Get("destination"), Protocol: values.Get("protocol"), Action: values.Get("action"), Reason: values.Get("reason"), RuleID: values.Get("ruleId"), Query: values.Get("q"), Cursor: values.Get("cursor")}
	if maximum == historyExportLimit {
		q.Limit = maximum
	}
	for key, all := range values {
		if len(all) != 1 {
			return q, fmt.Errorf("tekrarlı parametre: %s", key)
		}
		switch key {
		case "from", "to", "source", "destination", "protocol", "action", "reason", "ruleId", "q", "cursor", "limit", "port", "policyVersion", "format":
		default:
			return q, fmt.Errorf("bilinmeyen filtre: %s", key)
		}
	}
	for key, dest := range map[string]*time.Time{"from": &q.From, "to": &q.To} {
		if value := values.Get(key); value != "" {
			stamp, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return q, fmt.Errorf("%s RFC3339 tarih/saat olmalı", key)
			}
			*dest = stamp.UTC()
		}
	}
	for _, dest := range []*string{&q.Source, &q.Destination} {
		if *dest != "" {
			ip, err := netip.ParseAddr(*dest)
			if err != nil || ip.Zone() != "" {
				return q, errors.New("kaynak/hedef filtresi tek bir IP adresi olmalı")
			}
			*dest = ip.Unmap().String()
		}
	}
	if q.Protocol != "" {
		switch q.Protocol {
		case "tcp", "udp", "icmp", "icmpv6", "arp", "other", "any":
		default:
			return q, errors.New("protokol filtresi geçersiz")
		}
	}
	if q.Action != "" && q.Action != "pass" && q.Action != "drop" && q.Action != "observe" {
		return q, errors.New("karar filtresi geçersiz")
	}
	if len(q.Reason) > 64 || len(q.RuleID) > 80 || len(q.Query) > 120 || len(q.Cursor) > 2048 {
		return q, errors.New("filtre uzunluk sınırı aşıldı")
	}
	if value := values.Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > maximum {
			return q, fmt.Errorf("sayfa boyutu 1..%d olmalı", maximum)
		}
		q.Limit = n
	}
	if value := values.Get("port"); value != "" {
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil || n == 0 {
			return q, errors.New("hedef port 1..65535 olmalı")
		}
		port := uint16(n)
		q.Port = &port
	}
	if value := values.Get("policyVersion"); value != "" {
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil || n == 0 || n > 1<<53 {
			return q, errors.New("politika sürümü geçersiz")
		}
		q.PolicyVersion = n
	}
	return q, nil
}

func historyBounds(q EventFilter, now time.Time) (string, []any, time.Time, time.Time, time.Time, *eventCursor, error) {
	anchor := now.UTC()
	var cursor *eventCursor
	fingerprintRaw, _ := json.Marshal(q)
	hash := sha256.Sum256(fingerprintRaw)
	fingerprint := hex.EncodeToString(hash[:])
	if q.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
		if err != nil {
			return "", nil, time.Time{}, time.Time{}, anchor, nil, errors.New("sayfalama imleci geçersiz")
		}
		var c eventCursor
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&c); err != nil || c.Filter != fingerprint || c.ID == "" || len(c.ID) > 128 || c.Anchor.IsZero() || c.Anchor.After(now.Add(time.Second)) || c.Anchor.Before(now.Add(-eventRetentionDays*24*time.Hour)) {
			return "", nil, time.Time{}, time.Time{}, anchor, nil, errors.New("imleç bu filtreye ait değil veya süresi doldu")
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			return "", nil, time.Time{}, time.Time{}, anchor, nil, errors.New("imleç yalnız tek kayıt içermeli")
		}
		stamp, err := time.Parse(storedTimeFormat, c.Timestamp)
		if err != nil || stamp.UTC().Format(storedTimeFormat) != c.Timestamp {
			return "", nil, time.Time{}, time.Time{}, anchor, nil, errors.New("imleç zamanı geçersiz")
		}
		anchor = c.Anchor
		cursor = &c
	}
	from, to := q.From, q.To
	if to.IsZero() || to.After(anchor) {
		to = anchor
	}
	if from.IsZero() {
		from = anchor.Add(-24 * time.Hour)
	}
	if !to.After(from) || to.Sub(from) > eventRetentionDays*24*time.Hour {
		return "", nil, from, to, anchor, cursor, errors.New("tarih aralığı pozitif ve en fazla30gün olmalı")
	}
	floor := now.UTC().Add(-eventRetentionDays * 24 * time.Hour)
	if !to.After(floor) {
		return "", nil, from, to, anchor, cursor, errors.New("seçilen aralık30günlük saklama süresinin dışında")
	}
	if from.Before(floor) {
		from = floor
	}
	where := "json_extract(payload,'$.simulated')=? AND timestamp>=? AND timestamp<=?"
	args := []any{q.Simulated, from.UTC().Format(storedTimeFormat), to.UTC().Format(storedTimeFormat)}
	for _, v := range []struct{ field, value string }{{"source", q.Source}, {"destination", q.Destination}, {"protocol", q.Protocol}, {"reason", q.Reason}, {"ruleId", q.RuleID}} {
		if v.value != "" {
			where += " AND json_extract(payload,'$." + v.field + "')=?"
			args = append(args, v.value)
		}
	}
	if q.Action == "observe" {
		where += " AND json_extract(payload,'$.action')='pass' AND json_extract(payload,'$.wouldDrop')=1"
	} else if q.Action != "" {
		where += " AND json_extract(payload,'$.action')=?"
		args = append(args, q.Action)
	}
	if q.Port != nil {
		where += " AND json_extract(payload,'$.destinationPort')=?"
		args = append(args, *q.Port)
	}
	if q.PolicyVersion != 0 {
		where += " AND json_extract(payload,'$.policyVersion')=?"
		args = append(args, q.PolicyVersion)
	}
	if q.Query != "" {
		where += ` AND lower(coalesce(json_extract(payload,'$.source'),'') || ' ' || coalesce(json_extract(payload,'$.destination'),'') || ' ' || coalesce(json_extract(payload,'$.sourcePort'),'') || ' ' || coalesce(json_extract(payload,'$.destinationPort'),'') || ' ' || coalesce(json_extract(payload,'$.ruleId'),'') || ' ' || coalesce(json_extract(payload,'$.reason'),'')) LIKE ? ESCAPE '\'`
		args = append(args, "%"+strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(strings.ToLower(q.Query))+"%")
	}
	return where, args, from, to, anchor, cursor, nil
}

func (s *Store) QueryEvents(ctx context.Context, q EventFilter) (EventHistory, error) {
	result := EventHistory{Items: []Event{}, Simulated: q.Simulated, Sampled: !q.Simulated, RetentionDays: eventRetentionDays, RecordLimit: eventRecordLimit, ExportLimit: historyExportLimit, GeneratedAt: time.Now().UTC()}
	if q.Limit < 1 || q.Limit > historyExportLimit {
		return result, fmt.Errorf("%w: sayfa boyutu sınır dışında", ErrHistoryFilter)
	}
	where, args, from, to, anchor, cursor, err := historyBounds(q, result.GeneratedAt)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrHistoryFilter, err)
	}
	result.From, result.To = from, to
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	pageWhere := where
	pageArgs := append([]any{}, args...)
	if cursor != nil {
		pageWhere += " AND (timestamp < ? OR (timestamp=? AND id<?))"
		pageArgs = append(pageArgs, cursor.Timestamp, cursor.Timestamp, cursor.ID)
	}
	rows, err := tx.QueryContext(ctx, "SELECT timestamp,id,payload FROM events WHERE "+pageWhere+" ORDER BY timestamp DESC,id DESC LIMIT ?", append(pageArgs, q.Limit+1)...)
	if err != nil {
		return result, err
	}
	var lastTimestamp, lastID string
	for rows.Next() {
		var stamp, id, raw string
		if err = rows.Scan(&stamp, &id, &raw); err != nil {
			rows.Close()
			return result, err
		}
		if len(result.Items) == q.Limit {
			result.HasMore = true
			break
		}
		var event Event
		if err = json.Unmarshal([]byte(raw), &event); err != nil {
			rows.Close()
			return result, err
		}
		result.Items = append(result.Items, event)
		lastTimestamp, lastID = stamp, id
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if result.HasMore {
		fingerprintRaw, _ := json.Marshal(q)
		hash := sha256.Sum256(fingerprintRaw)
		raw, _ := json.Marshal(eventCursor{Timestamp: lastTimestamp, ID: lastID, Anchor: anchor, Filter: hex.EncodeToString(hash[:])})
		result.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	err = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(json_extract(payload,'$.action')='pass'),0),coalesce(sum(json_extract(payload,'$.action')='drop'),0),coalesce(sum(json_extract(payload,'$.wouldDrop')=1 AND json_extract(payload,'$.action')='pass'),0),coalesce(sum(json_extract(payload,'$.length')),0),count(DISTINCT nullif(json_extract(payload,'$.source'),'')) FROM events WHERE `+where, args...).Scan(&result.Summary.MatchedEvents, &result.Summary.PassedEvents, &result.Summary.DroppedEvents, &result.Summary.WouldDropEvents, &result.Summary.SampleBytes, &result.Summary.UniqueSources)
	if err != nil {
		return result, err
	}
	for _, group := range []struct {
		field string
		dest  *[]NamedCount
	}{{"protocol", &result.Summary.Protocols}, {"reason", &result.Summary.Reasons}, {"source", &result.Summary.Sources}, {"ruleId", &result.Summary.Rules}, {"hour", &result.Summary.Timeline}} {
		expression := "coalesce(json_extract(payload,'$." + group.field + "'),'')"
		order := "count(*) DESC,label ASC LIMIT 10"
		if group.field == "hour" {
			expression = "substr(timestamp,1,13)||':00:00Z'"
			order = "label ASC LIMIT 721"
		}
		items := []NamedCount{}
		r, err := tx.QueryContext(ctx, "SELECT "+expression+" AS label,count(*) FROM events WHERE "+where+" GROUP BY label ORDER BY "+order, args...)
		if err != nil {
			return result, err
		}
		for r.Next() {
			var v NamedCount
			if err = r.Scan(&v.Label, &v.Count); err != nil {
				r.Close()
				return result, err
			}
			items = append(items, v)
		}
		err = r.Err()
		r.Close()
		if err != nil {
			return result, err
		}
		*group.dest = items
	}
	var oldest sql.NullString
	err = tx.QueryRowContext(ctx, "SELECT count(*),min(timestamp) FROM events WHERE json_extract(payload,'$.simulated')=? AND timestamp>=?", q.Simulated, result.GeneratedAt.Add(-eventRetentionDays*24*time.Hour).Format(storedTimeFormat)).Scan(&result.RetainedEvents, &oldest)
	if err != nil {
		return result, err
	}
	if oldest.Valid {
		result.OldestAvailable = oldest.String
	}
	return result, tx.Commit()
}
