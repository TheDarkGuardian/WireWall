package control

import (
	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
	"testing"
	"time"
)

func TestConfirmedResumeRequiresExactDeployment(t *testing.T) {
	now := time.Now().UTC()
	p := policy.Default()
	b := model.Ban{ID: "b", Address: "192.0.2.4", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	r := resumeRecord{Version: 1, Policy: p, Bans: []model.Ban{b}, Identity: "identity", ConfirmedAt: now}
	if !matchesResume(r, p, []model.Ban{b}, "identity", now) {
		t.Fatal("confirmed deployment refused")
	}
	changed := p
	changed.Version++
	if matchesResume(r, changed, []model.Ban{b}, "identity", now) {
		t.Fatal("unconfirmed version resumed")
	}
	if matchesResume(r, p, []model.Ban{b}, "new-binary", now) {
		t.Fatal("changed artifact resumed")
	}
	if matchesResume(r, p, nil, "identity", now) {
		t.Fatal("unconfirmed ban removal resumed")
	}
	later := now.Add(2 * time.Minute)
	if !matchesResume(r, p, nil, "identity", later) {
		t.Fatal("natural ban expiry must not prevent resume")
	}
	b.ExpiresAt = later.Add(time.Hour)
	if matchesResume(r, p, []model.Ban{b}, "identity", later) {
		t.Fatal("extended TTL resumed")
	}
}
