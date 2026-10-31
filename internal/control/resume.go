package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

// Explicit --resume-confirmed permits continuity of a previously SSH-confirmed
// deployment. A mismatch takes guarded startup; no pending guard is canceled.
type resumeRecord struct {
	Version     int          `json:"version"`
	Policy      model.Policy `json:"policy"`
	Bans        []model.Ban  `json:"bans"`
	Identity    string       `json:"identity"`
	ConfirmedAt time.Time    `json:"confirmedAt"`
}

func deploymentIdentity(p model.Policy, object string) (string, error) {
	iface, err := net.InterfaceByName(p.Interface)
	if err != nil {
		return "", err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	parts := []string{iface.Name, iface.HardwareAddr.String()}
	var ips []string
	for _, address := range addresses {
		ips = append(ips, address.String())
	}
	sort.Strings(ips)
	parts = append(parts, ips...)
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	for _, path := range []string{executable, object} {
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return "", errors.Join(copyErr, closeErr)
		}
		parts = append(parts, hex.EncodeToString(hash.Sum(nil)))
	}
	raw, err := json.Marshal(parts)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}
func activeResumeBans(bans []model.Ban, now time.Time) []model.Ban {
	out := []model.Ban{}
	for _, ban := range bans {
		if ban.ExpiresAt.After(now) {
			out = append(out, ban)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func matchesResume(record resumeRecord, p model.Policy, bans []model.Ban, identity string, now time.Time) bool {
	// Canonical JSON excludes Go's monotonic time metadata, includes version/TTL.
	rawPolicy, _ := json.Marshal(p)
	rawRecord, _ := json.Marshal(record.Policy)
	rawBans, _ := json.Marshal(activeResumeBans(bans, now))
	rawOldBans, _ := json.Marshal(activeResumeBans(record.Bans, now))
	return record.Version == 1 && record.Identity == identity && identity != "" && !record.ConfirmedAt.IsZero() && string(rawPolicy) == string(rawRecord) && string(rawBans) == string(rawOldBans)
}
func readResume(dataDir string) (resumeRecord, error) {
	var record resumeRecord
	path := filepath.Join(dataDir, "confirmed-startup.json")
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 2<<20 {
		return record, errors.New("confirmed startup record must be private and regular")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	err = json.Unmarshal(raw, &record)
	return record, err
}
func (r *XDPRuntime) rememberConfirmed() error {
	return writeGuardJSON(filepath.Join(r.dataDir, "confirmed-startup.json"), resumeRecord{Version: 1, Policy: r.policy, Bans: r.bans, Identity: r.identity, ConfirmedAt: time.Now().UTC()})
}
