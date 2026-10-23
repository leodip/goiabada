// Package statuswriter is the response writer the request logger and the HTTP metrics read a
// response's status and size through. It answers as chi's WrapResponseWriter did, so the records
// and the counters say what they said before #462.
package statuswriter

import "net/http"

// Writer passes everything to the writer it wraps and remembers the first final status and the
// bytes of the body.
type Writer struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

// Wrap answers a Writer over w.
func Wrap(w http.ResponseWriter) *Writer {
	return &Writer{ResponseWriter: w}
}

// WriteHeader passes an informational status on without taking it for the response's, since a
// final one follows; 101 is final, because the connection is the handler's after it. A status after
// the first final one is neither recorded nor passed on.
func (w *Writer) WriteHeader(code int) {
	if code >= 100 && code <= 199 && code != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	if w.wroteHeader {
		return
	}
	w.status = code
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

// Write answers 200 first when no status was written, as net/http does.
func (w *Writer) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// Status is the first final status written, or 0 when nothing was: a handler that returned
// without answering, or one that panicked before it did.
func (w *Writer) Status() int {
	return w.status
}

// BytesWritten is the size of the body written so far.
func (w *Writer) BytesWritten() int {
	return w.bytes
}

// Unwrap answers the writer beneath, which is how http.ResponseController reaches its Flush,
// Hijack and deadlines through this one.
func (w *Writer) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
