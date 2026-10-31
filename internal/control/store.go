package control

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

const storedTimeFormat = "2006-01-02T15:04:05.000000000Z07:00"
const eventRetentionDays = 30
const eventRecordLimit = 100000

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "wirewall.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000", "PRAGMA synchronous=FULL", "PRAGMA max_page_count=32768",
		`CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), policy TEXT NOT NULL, bans TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, payload TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS events_time_id ON events(timestamp DESC,id DESC)`,
		`CREATE INDEX IF NOT EXISTS events_source_time ON events(json_extract(payload,'$.simulated'),timestamp DESC,id DESC)`,
	} {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite migration: %w", err)
		}
	}
	return &Store{db: db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Load() (model.Policy, []model.Ban, bool, error) {
	var p model.Policy
	var bans []model.Ban
	var rawP, rawB string
	err := s.db.QueryRow("SELECT policy,bans FROM state WHERE id=1").Scan(&rawP, &rawB)
	if err == sql.ErrNoRows {
		return p, []model.Ban{}, false, nil
	}
	if err != nil {
		return p, nil, false, err
	}
	if err = json.Unmarshal([]byte(rawP), &p); err != nil {
		return p, nil, false, err
	}
	if err = json.Unmarshal([]byte(rawB), &bans); err != nil {
		return p, nil, false, err
	}
	return p, bans, true, nil
}
func (s *Store) Save(p model.Policy, bans []model.Ban, action, detail string) error {
	rawP, err := json.Marshal(p)
	if err != nil {
		return err
	}
	rawB, err := json.Marshal(bans)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("INSERT INTO state(id,policy,bans) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET policy=excluded.policy,bans=excluded.bans", string(rawP), string(rawB)); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO audit(id,timestamp,action,detail) VALUES(?,?,?,?)", newID(), time.Now().UTC().Format(storedTimeFormat), action, detail); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY timestamp DESC LIMIT 5000)"); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) SaveEvents(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, event := range events {
		raw, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, err = tx.Exec("INSERT OR IGNORE INTO events(id,timestamp,payload) VALUES(?,?,?)", event.ID, event.Timestamp.UTC().Format(storedTimeFormat), string(raw)); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("DELETE FROM events WHERE timestamp < ?", time.Now().UTC().Add(-eventRetentionDays*24*time.Hour).Format(storedTimeFormat)); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY timestamp DESC,id DESC LIMIT -1 OFFSET ?)", eventRecordLimit); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LoadEvents(limit int, simulated bool) ([]Event, error) {
	if limit < 1 || limit > 300 {
		limit = 300
	}
	rows, err := s.db.Query("SELECT payload FROM events WHERE json_extract(payload,'$.simulated') = ? AND timestamp >= ? ORDER BY timestamp DESC,id DESC LIMIT ?", simulated, time.Now().UTC().Add(-eventRetentionDays*24*time.Hour).Format(storedTimeFormat), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []Event{}
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var event Event
		if err = json.Unmarshal([]byte(raw), &event); err != nil {
			return nil, fmt.Errorf("stored event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) ClearLabEvents() error {
	_, err := s.db.Exec("DELETE FROM events WHERE json_extract(payload,'$.simulated') = 1")
	return err
}
func (s *Store) Audit(limit int) ([]Audit, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query("SELECT id,timestamp,action,detail FROM audit ORDER BY timestamp DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Audit{}
	for rows.Next() {
		var a Audit
		var stamp string
		if err = rows.Scan(&a.ID, &stamp, &a.Action, &a.Detail); err != nil {
			return nil, err
		}
		a.Timestamp, _ = time.Parse(time.RFC3339Nano, stamp)
		out = append(out, a)
	}
	return out, rows.Err()
}
