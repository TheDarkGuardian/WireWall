package control

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func (h *HTTPServer) eventHistory(w http.ResponseWriter, r *http.Request) {
	h.queryHistory(w, r, false)
}
func (h *HTTPServer) eventHistoryExport(w http.ResponseWriter, r *http.Request) {
	h.queryHistory(w, r, true)
}
func (h *HTTPServer) queryHistory(w http.ResponseWriter, r *http.Request, export bool) {
	maximum := 200
	if export {
		maximum = historyExportLimit
	}
	filter, err := parseEventFilter(r.URL.Query(), h.service.backend == "lab", maximum)
	if err != nil {
		fail(w, 400, err)
		return
	}
	format := r.URL.Query().Get("format")
	if export && format != "json" && format != "csv" {
		fail(w, 400, errors.New("format json veya csv olmalı"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	result, err := h.service.store.QueryEvents(ctx, filter)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			fail(w, 503, errors.New("geçmiş sorgusu süre sınırına ulaştı; aralığı daraltın"))
		} else if errors.Is(err, ErrHistoryFilter) {
			fail(w, 400, err)
		} else {
			fail(w, 500, errors.New("olay geçmişi okunamadı"))
		}
		return
	}
	if !export {
		respond(w, 200, result)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="wirewall-events-%s.%s"`, time.Now().UTC().Format("20060102T150405Z"), format))
	w.Header().Set("X-WireWall-Matched-Events", strconv.FormatUint(result.Summary.MatchedEvents, 10))
	w.Header().Set("X-WireWall-Export-Truncated", strconv.FormatBool(result.HasMore))
	w.Header().Set("X-WireWall-Export-Limit", strconv.Itoa(historyExportLimit))
	if result.NextCursor != "" {
		w.Header().Set("X-WireWall-Next-Cursor", result.NextCursor)
	}
	if format == "json" {
		respond(w, 200, result)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	_, _ = w.Write([]byte{0xef, 0xbb, 0xbf})
	writer := csv.NewWriter(w)
	writer.UseCRLF = true
	_ = writer.Write([]string{"timestamp", "source", "destination", "sourcePort", "destinationPort", "protocol", "length", "action", "reason", "ruleId", "wouldDrop", "simulated", "policyVersion"})
	for _, e := range result.Items {
		version := ""
		if e.PolicyVersion != 0 {
			version = strconv.FormatUint(e.PolicyVersion, 10)
		}
		values := []string{e.Timestamp.UTC().Format(time.RFC3339Nano), e.Source, e.Destination, strconv.Itoa(int(e.SourcePort)), strconv.Itoa(int(e.DestinationPort)), e.Protocol, strconv.FormatUint(uint64(e.Length), 10), e.Action, e.Reason, e.RuleID, strconv.FormatBool(e.WouldDrop), strconv.FormatBool(e.Simulated), version}
		for i, v := range values {
			values[i] = safeCSVCell(v)
		}
		if writer.Write(values) != nil {
			return
		}
	}
	writer.Flush()
}
func safeCSVCell(value string) string {
	trimmed := strings.TrimLeftFunc(value, unicode.IsSpace)
	if strings.HasPrefix(value, "\t") || strings.HasPrefix(value, "\r") || strings.HasPrefix(value, "\n") || trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}
