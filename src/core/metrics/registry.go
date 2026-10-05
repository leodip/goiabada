// Package metrics is the Prometheus metrics both servers expose: counters, gauges and fixed-bucket
// histograms held in a Registry, the text exposition format 0.0.4 its Handler writes, the HTTP
// middleware recording requests by route, and the build-info and runtime gauges.
//
// It is written here rather than taken from prometheus/client_golang, which adds eight modules and
// about 2.1 MB to the auth server, links expvar for good, and takes any string as a label value
// (#400 decision 2). The last is the one this package exists to refuse: every label is declared with
// the closed set of values it may take, and a value outside the set is recorded as "other", so no
// request, however crafted, can grow a family past the product of its sets. Nothing taken from a
// request or from the database reaches a label without being mapped into a declared set first: no
// user, client identifier, address, path or error description (#400 decision 4).
package metrics

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// other is the value a label records for anything outside its declared set.
const other = "other"

// The three family types this package writes, spelled as the TYPE line spells them.
const (
	typeCounter   = "counter"
	typeGauge     = "gauge"
	typeHistogram = "histogram"
)

// The names Prometheus can read: a metric name may hold a colon, a label name may not, and a label
// name beginning with two underscores is reserved for Prometheus's own.
var (
	metricNamePattern = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelNamePattern  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// Label is one label of a family and the closed set of values it may take, declared with Enum or
// Described when the family is registered.
type Label struct {
	name        string
	description string
	values      func() []string
	// described marks a set the catalog names in words, which therefore needs the words.
	described bool
	// deferred marks a set read when the family is first used rather than when it is registered,
	// which is how a route label reads a router whose routes are added after its middleware.
	deferred bool
}

// Enum declares a label whose values the metrics catalog lists one by one.
func Enum(name string, values ...string) Label {
	declared := slices.Clone(values)
	return Label{name: name, values: func() []string { return declared }}
}

// Described declares a label whose set the metrics catalog names in words rather than listing,
// because it is too long to list, such as the status codes, or is this binary's own, such as its
// version. The description is what the catalog's cell for the label must say.
func Described(name, description string, values ...string) Label {
	declared := slices.Clone(values)
	return Label{name: name, description: description, described: true, values: func() []string { return declared }}
}

// Name is the label's name.
func (l Label) Name() string { return l.name }

// Description is what the catalog says the set is, or "" for a set it lists.
func (l Label) Description() string { return l.description }

// Values is the declared set, in declaration order.
func (l Label) Values() []string { return slices.Clone(l.values()) }

// Family describes one registered family as the metrics catalog check reads it.
type Family struct {
	Name   string
	Type   string
	Help   string
	Labels []Label
}

// Registry holds the families one server exposes. A family is registered once, at startup, and
// recorded in from any goroutine.
type Registry struct {
	mu       sync.Mutex
	families map[string]*family
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{families: map[string]*family{}}
}

// Counter registers a counter: a value that only goes up.
//
// Registration panics on a family Prometheus could not read or this package could not bound: a
// name registered twice, a name or label name outside Prometheus's grammar, an empty help, a label
// declared twice or with no values, an empty or repeated value. Each is a programming error at a
// composition root, made once at startup, and no request can cause one.
func (r *Registry) Counter(name, help string, labels ...Label) *Counter {
	return &Counter{r.register(name, help, typeCounter, labels, nil, nil)}
}

// Gauge registers a gauge: a value that is set, or goes up and down.
func (r *Registry) Gauge(name, help string, labels ...Label) *Gauge {
	return &Gauge{r.register(name, help, typeGauge, labels, nil, nil)}
}

// GaugeFunc registers an unlabeled gauge whose value is read from read at every scrape, for a
// value something else already keeps, such as the runtime's goroutine count.
func (r *Registry) GaugeFunc(name, help string, read func() float64) {
	if read == nil {
		panic(fmt.Sprintf("metrics: %s is a gauge read at scrape time with nothing to read", name))
	}
	r.register(name, help, typeGauge, nil, nil, read)
}

// Histogram registers a histogram with fixed buckets, given as their upper bounds in ascending
// order; the +Inf bucket is always added and must not be given.
func (r *Registry) Histogram(name, help string, buckets []float64, labels ...Label) *Histogram {
	if len(buckets) == 0 {
		panic(fmt.Sprintf("metrics: %s is a histogram with no buckets", name))
	}
	for i, bound := range buckets {
		if math.IsNaN(bound) || math.IsInf(bound, 0) {
			panic(fmt.Sprintf("metrics: %s has the bucket %v; buckets are finite, and +Inf is always added", name, bound))
		}
		if i > 0 && bound <= buckets[i-1] {
			panic(fmt.Sprintf("metrics: %s has buckets that do not strictly increase at %v", name, bound))
		}
	}
	for _, label := range labels {
		if label.name == "le" {
			panic(fmt.Sprintf("metrics: %s declares the label le, which a histogram's buckets use", name))
		}
	}
	return &Histogram{r.register(name, help, typeHistogram, labels, slices.Clone(buckets), nil)}
}

// Families describes every registered family, in name order, each label carrying its declared set.
// A set read from a router is read here if nothing has read it yet.
func (r *Registry) Families() []Family {
	out := make([]Family, 0)
	for _, f := range r.sorted() {
		labels := make([]Label, len(f.labels))
		for i, set := range f.resolved() {
			values := set.values
			labels[i] = Label{name: set.name, description: set.description, values: func() []string { return values }}
		}
		out = append(out, Family{Name: f.name, Type: f.typ, Help: f.help, Labels: labels})
	}
	return out
}

func (r *Registry) register(name, help, typ string, labels []Label, buckets []float64, read func() float64) *family {
	if !metricNamePattern.MatchString(name) {
		panic(fmt.Sprintf("metrics: %q is not a metric name Prometheus can read", name))
	}
	if help == "" {
		panic(fmt.Sprintf("metrics: %s has no help", name))
	}
	deferred := false
	seen := map[string]bool{}
	for _, label := range labels {
		if !labelNamePattern.MatchString(label.name) || strings.HasPrefix(label.name, "__") {
			panic(fmt.Sprintf("metrics: %s declares %q, which is not a label name Prometheus allows", name, label.name))
		}
		if seen[label.name] {
			panic(fmt.Sprintf("metrics: %s declares the label %s twice", name, label.name))
		}
		seen[label.name] = true
		if label.described && strings.TrimSpace(label.description) == "" {
			panic(fmt.Sprintf("metrics: %s describes the label %s with no description", name, label.name))
		}
		deferred = deferred || label.deferred
	}

	f := &family{
		name:    name,
		help:    help,
		typ:     typ,
		labels:  slices.Clone(labels),
		buckets: buckets,
		read:    read,
		series:  map[string]*series{},
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, taken := r.families[name]; taken {
		panic(fmt.Sprintf("metrics: %s is registered twice", name))
	}
	// A set known now is checked now, so a bad one stops startup rather than the first request.
	if !deferred {
		f.resolved()
	}
	r.families[name] = f
	return f
}

// sorted returns the families in name order, which is the order the exposition writes them in.
func (r *Registry) sorted() []*family {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]*family, 0, len(r.families))
	for _, f := range r.families {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// labelSet is a label's declared set as a family records against it.
type labelSet struct {
	name        string
	description string
	values      []string
	members     map[string]bool
}

type family struct {
	name, help, typ string
	labels          []Label
	buckets         []float64
	read            func() float64

	once sync.Once
	sets []labelSet

	mu     sync.RWMutex
	series map[string]*series
}

// resolved reads every label's set once, checks it, and creates the one series an unlabeled family
// has, so it reads zero before anything is recorded in it.
func (f *family) resolved() []labelSet {
	f.once.Do(func() {
		sets := make([]labelSet, len(f.labels))
		for i, label := range f.labels {
			values := label.values()
			if len(values) == 0 {
				panic(fmt.Sprintf("metrics: %s declares the label %s with no values", f.name, label.name))
			}
			members := make(map[string]bool, len(values))
			for _, v := range values {
				if v == "" {
					panic(fmt.Sprintf("metrics: %s declares an empty value for %s", f.name, label.name))
				}
				if members[v] {
					panic(fmt.Sprintf("metrics: %s declares the value %q for %s twice", f.name, v, label.name))
				}
				members[v] = true
			}
			sets[i] = labelSet{name: label.name, description: label.description, values: slices.Clone(values), members: members}
		}
		f.sets = sets
		if len(sets) == 0 && f.read == nil {
			f.series[""] = f.newSeries(nil)
		}
	})
	return f.sets
}

func (f *family) newSeries(values []string) *series {
	s := &series{values: values}
	if f.typ == typeHistogram {
		s.counts = make([]uint64, len(f.buckets)+1)
	}
	return s
}

// seriesFor returns the series for the given label values, each mapped into its declared set
// first: a value outside it is recorded as other. A count of values that is not the number of
// labels declared is a programming error, and panics.
func (f *family) seriesFor(values []string) *series {
	sets := f.resolved()
	if len(values) != len(sets) {
		panic(fmt.Sprintf("metrics: %s has %d labels and was recorded with %d values", f.name, len(sets), len(values)))
	}
	mapped := make([]string, len(values))
	for i, v := range values {
		if sets[i].members[v] {
			mapped[i] = v
		} else {
			mapped[i] = other
		}
	}
	key := strings.Join(mapped, "\xff")

	f.mu.RLock()
	s := f.series[key]
	f.mu.RUnlock()
	if s != nil {
		return s
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if s = f.series[key]; s == nil {
		s = f.newSeries(mapped)
		f.series[key] = s
	}
	return s
}

// snapshot returns the family's series ordered by their label values, label by label.
func (f *family) snapshot() []*series {
	f.resolved()
	f.mu.RLock()
	out := make([]*series, 0, len(f.series))
	for _, s := range f.series {
		out = append(out, s)
	}
	f.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return slices.Compare(out[i].values, out[j].values) < 0 })
	return out
}

// series is one combination of label values. A counter or gauge keeps its value as float64 bits,
// updated atomically; a histogram keeps its buckets, sum and count under a lock, so a scrape never
// reads a count that disagrees with its +Inf bucket.
type series struct {
	values []string
	bits   atomic.Uint64

	mu     sync.Mutex
	counts []uint64
	sum    float64
	count  uint64
}

func (s *series) add(delta float64) {
	for {
		old := s.bits.Load()
		if s.bits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+delta)) {
			return
		}
	}
}

func (s *series) value() float64 { return math.Float64frombits(s.bits.Load()) }

// Counter is a registered counter.
type Counter struct{ f *family }

// Inc adds one to the series the label values name.
func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Add adds delta, which must not be negative, to the series the label values name.
func (c *Counter) Add(delta float64, labelValues ...string) {
	if delta < 0 || math.IsNaN(delta) {
		panic(fmt.Sprintf("metrics: %s is a counter and was given %v; a counter only goes up", c.f.name, delta))
	}
	c.f.seriesFor(labelValues).add(delta)
}

// Gauge is a registered gauge.
type Gauge struct{ f *family }

// Set sets the series the label values name to v.
func (g *Gauge) Set(v float64, labelValues ...string) {
	g.f.seriesFor(labelValues).bits.Store(math.Float64bits(v))
}

// Add adds delta, which may be negative, to the series the label values name.
func (g *Gauge) Add(delta float64, labelValues ...string) {
	g.f.seriesFor(labelValues).add(delta)
}

// Histogram is a registered histogram.
type Histogram struct{ f *family }

// Observe records v in the series the label values name: in the first bucket whose upper bound is
// at or above it, or in +Inf.
func (h *Histogram) Observe(v float64, labelValues ...string) {
	s := h.f.seriesFor(labelValues)
	i := sort.SearchFloat64s(h.f.buckets, v)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[i]++
	s.sum += v
	s.count++
}
