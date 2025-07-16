module github.com/csobrinho/traefik-s3-forward-auth

go 1.24

toolchain go1.24.5

require (
	github.com/sirupsen/logrus v1.9.3
	github.com/thomseddon/go-flags v1.4.1-0.20190507184247-a3629c504486
	github.com/traefik/traefik/v2 v2.11.2
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/containous/alice v0.0.0-20181107144136-d83ebdd94cbd // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/gravitational/trace v1.4.0 // indirect
	github.com/miekg/dns v1.1.59 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/traefik/paerser v0.2.0 // indirect
	github.com/vulcand/predicate v1.2.0 // indirect
	golang.org/x/mod v0.23.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/tools v0.30.0 // indirect
)

// Containous forks
replace github.com/gorilla/mux => github.com/containous/mux v0.0.0-20250523120546-41b6ec3aed59
