package metrics

import (
	"bytes"
	"math"
	"net/http"
	"strconv"
	"strings"
)

// contentType is the text exposition format 0.0.4's media type. Prometheus 3 fails a scrape whose
// Content-Type is missing or one it cannot parse, and still lists PrometheusText0.0.4 among its
// default scrape protocols.
const contentType = "text/plain; version=0.0.4; charset=utf-8"

// Handler serves the registry's exposition. It answers whatever reaches it: which path and which
// methods reach it is the metrics listener's own mux to decide.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var body bytes.Buffer
		r.write(&body)

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
		w.WriteHeader(http.StatusOK)
		// The status is already sent; a client that went away before reading the body leaves
		// nothing to answer.
		_, _ = w.Write(body.Bytes())
	})
}

// write renders every family in the text exposition format 0.0.4: a HELP and a TYPE line, then one
// line per sample, families in name order and series in the order of their label values. A
// histogram's buckets are cumulative and end in +Inf, followed by _sum and _count. No sample
// carries a timestamp: the scraper stamps it.
func (r *Registry) write(b *bytes.Buffer) {
	for _, f := range r.sorted() {
		b.WriteString("# HELP " + f.name + " " + escapeHelp(f.help) + "\n")
		b.WriteString("# TYPE " + f.name + " " + f.typ + "\n")

		names := make([]string, len(f.resolved()))
		for i, set := range f.resolved() {
			names[i] = set.name
		}
		for _, s := range f.snapshot() {
			if f.typ != typeHistogram {
				writeSample(b, f.name, names, s.values, "", formatFloat(s.value()))
				continue
			}

			s.mu.Lock()
			counts, sum, count := append([]uint64(nil), s.counts...), s.sum, s.count
			s.mu.Unlock()

			var cumulative uint64
			for i, bound := range f.buckets {
				cumulative += counts[i]
				writeSample(b, f.name+"_bucket", names, s.values, formatFloat(bound), strconv.FormatUint(cumulative, 10))
			}
			writeSample(b, f.name+"_bucket", names, s.values, "+Inf", strconv.FormatUint(count, 10))
			writeSample(b, f.name+"_sum", names, s.values, "", formatFloat(sum))
			writeSample(b, f.name+"_count", names, s.values, "", strconv.FormatUint(count, 10))
		}
	}
}

// writeSample writes one sample line; le, when not empty, is written as the last label.
func writeSample(b *bytes.Buffer, name string, labels, values []string, le, value string) {
	b.WriteString(name)
	if len(labels) > 0 || le != "" {
		b.WriteByte('{')
		for i, label := range labels {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(label + `="` + escapeLabelValue(values[i]) + `"`)
		}
		if le != "" {
			if len(labels) > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`le="` + le + `"`)
		}
		b.WriteByte('}')
	}
	b.WriteString(" " + value + "\n")
}

// A label value escapes the backslash, the double quote and the line feed; a HELP line escapes the
// backslash and the line feed only.
var (
	labelValueEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	helpEscaper       = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

func escapeLabelValue(v string) string { return labelValueEscaper.Replace(v) }

func escapeHelp(h string) string { return helpEscaper.Replace(h) }

// formatFloat writes a value as Go's ParseFloat reads it back, which is what the format asks for,
// with Prometheus's own spellings of the infinities and NaN.
func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
