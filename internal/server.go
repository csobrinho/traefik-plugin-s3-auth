package tsfa

import (
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
	muxhttp "github.com/traefik/traefik/v2/pkg/muxer/http"
)

// Server contains muxer and handler methods.
type Server struct {
	muxer *muxhttp.Muxer
}

// NewServer creates a new server object and builds muxer.
func NewServer() *Server {
	s := &Server{}
	s.buildRoutes()
	return s
}

// RootHandler overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by mux.
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	log.Infof("%s %s", r.Method, r.URL.Path)
	log.Infof("Host: %s", r.Host)
	for k, v := range r.Header {
		log.Infof("%s: %s", k, v)
	}

	// Modify request.
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")

	// Read URI from header if we're acting as forward auth middleware.
	if _, ok := r.Header["X-Forwarded-Uri"]; ok {
		r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
	}

	// Pass to mux.
	s.muxer.ServeHTTP(w, r)
}

// AuthHandler Authenticates requests.
func (s *Server) AuthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger(r, "Auth", "Authenticating request")

		err := ValidateHeader(r, config.HeaderName, config.Credentials)
		if err != nil {
			logger.WithError(err).Debug("Invalid request")
			http.Error(w, http.StatusText(config.StatusCode), config.StatusCode)
			return
		}

		// Valid request.
		logger.Debug("Allowing valid request")
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) buildRoutes() {
	var err error
	s.muxer, err = muxhttp.NewMuxer()
	if err != nil {
		log.Fatal(err)
	}
	// Add a default handler.
	s.muxer.NewRoute().Handler(s.AuthHandler())
}

func (s *Server) logger(r *http.Request, handler, msg string) *logrus.Entry {
	logger := log.WithFields(logrus.Fields{
		"handler":   handler,
		"method":    r.Header.Get("X-Forwarded-Method"),
		"proto":     r.Header.Get("X-Forwarded-Proto"),
		"host":      r.Header.Get("X-Forwarded-Host"),
		"uri":       r.Header.Get("X-Forwarded-Uri"),
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})
	logger.WithFields(logrus.Fields{"authorization": r.Header.Get(config.HeaderName)}).Debug(msg)

	return logger
}
