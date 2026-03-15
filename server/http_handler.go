package server

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/fisker/zvpn/vpn/openconnect"
)

type tlsErrorLogger struct {
	normalErrors map[string]bool
}

func (l *tlsErrorLogger) Write(p []byte) (n int, err error) {
	msg := string(p)
	msgLower := strings.ToLower(msg)
	for normalErr := range l.normalErrors {
		if strings.Contains(msgLower, strings.ToLower(normalErr)) {
			return len(p), nil
		}
	}
	log.Printf("TLS: ERROR - %s", strings.TrimSpace(msg))
	if strings.Contains(msgLower, "handshake") {
		log.Printf("TLS: Handshake error - check cert validation, cipher suite, or network")
	} else if strings.Contains(msgLower, "certificate") {
		log.Printf("TLS: Certificate-related error")
	} else if strings.Contains(msgLower, "timeout") {
		log.Printf("TLS: Timeout - connection may be slow")
	}
	return len(p), nil
}

type keepAliveResponseWriter struct {
	http.ResponseWriter
	written    bool
	statusCode int
}

func (w *keepAliveResponseWriter) WriteHeader(code int) {
	if !w.written {
		w.Header().Set("Connection", "keep-alive")
		w.written = true
		w.statusCode = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *keepAliveResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *keepAliveResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *keepAliveResponseWriter) CloseNotify() <-chan bool {
	if cn, ok := w.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	return make(chan bool)
}

func (w *keepAliveResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseWriter does not implement http.Hijacker")
}

type connectHandler struct {
	ginHandler http.Handler
	ocHandler  *openconnect.Handler
}

func (h *connectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method, path := r.Method, r.URL.Path
	isVPNClient := isVPNClientRequest(r)
	if isVPNClient {
		clientConnection := strings.ToLower(r.Header.Get("Connection"))
		if method == http.MethodGet && clientConnection == "close" {
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if method == http.MethodPost && clientConnection == "close" {
			r.Header.Set("Connection", "keep-alive")
		}
	}
	wrappedWriter := &keepAliveResponseWriter{ResponseWriter: w}
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("HTTP: Panic in handler %s %s: %v", method, path, rec)
			if !wrappedWriter.written {
				wrappedWriter.WriteHeader(http.StatusInternalServerError)
				wrappedWriter.Write([]byte("Internal Server Error"))
			}
			panic(rec)
		}
	}()
	startTime := time.Now()
	h.ginHandler.ServeHTTP(wrappedWriter, r)
	log.Printf("HTTP: %s %s - %d - %v", method, path, wrappedWriter.statusCode, time.Since(startTime))
}

func isVPNClientRequest(r *http.Request) bool {
	xAggregateAuth := r.Header.Get("X-Aggregate-Auth")
	xTranscendVersion := r.Header.Get("X-Transcend-Version")
	userAgent := strings.ToLower(r.UserAgent())
	return (xAggregateAuth == "1" && xTranscendVersion == "1") ||
		strings.Contains(userAgent, "anyconnect") ||
		strings.Contains(userAgent, "openconnect") ||
		strings.Contains(userAgent, "cisco secure client") ||
		strings.Contains(userAgent, "cisco anyconnect") ||
		(xAggregateAuth != "" && xTranscendVersion != "")
}
