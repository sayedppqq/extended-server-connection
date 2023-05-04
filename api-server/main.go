package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sayedppqq/extended-server-connection/lib/certstore"
	"github.com/sayedppqq/extended-server-connection/lib/server"
	"github.com/spf13/afero"
	"io"
	"k8s.io/client-go/util/cert"
	"log"
	"net"
	"net/http"
	"time"
)

func main() {
	// proxy is used to determine is this server used as a proxy
	// to another server
	var proxy = false
	flag.BoolVar(&proxy, "send-proxy-request", proxy, "forward req to eas")
	flag.Parse()

	fs := afero.NewOsFs()
	store, err := certstore.NewCertStore(fs, "/tmp/extended-server-connection")
	if err != nil {
		log.Fatalln(err)
	}
	err = store.NewCA("apiserver")
	if err != nil {
		log.Fatalln(err)
	}

	serverCert, serverKey, err := store.NewServerCertPair(cert.AltNames{
		IPs: []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.Write("tls", serverCert, serverKey)

	clientCert, clientKey, err := store.NewClientCertPair(cert.AltNames{
		DNSNames: []string{"john"},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.Write("john", clientCert, clientKey)
	if err != nil {
		log.Fatalln(err)
	}

	// Another cert and key for making request to eas from as.
	// Because a client is making request to eas through as.
	rhStore, err := certstore.NewCertStore(fs, "/tmp/extended-server-connection")
	if err != nil {
		log.Fatalln(err)
	}
	err = rhStore.InitCA("requestheader")
	if err != nil {
		log.Fatalln(err)
	}
	rhClientCert, rhClientKey, err := rhStore.NewClientCertPair(cert.AltNames{
		DNSNames: []string{"apiserver"}, // because apiserver is making the calls to database eas
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = rhStore.Write("apiserver", rhClientCert, rhClientKey)
	if err != nil {
		log.Fatalln(err)
	}
	rhCert, err := tls.LoadX509KeyPair(rhStore.CertFile("apiserver"), rhStore.KeyFile("apiserver"))
	if err != nil {
		log.Fatalln(err)
	}

	// This certpool will be used to verify eas certificates. It holds CA of server
	easCACertPool := x509.NewCertPool()
	if proxy {
		easStore, err := certstore.NewCertStore(fs, "/tmp/extended-server-connection")
		if err != nil {
			log.Fatalln(err)
		}
		err = easStore.LoadCA("extended")
		if err != nil {
			log.Fatalln(err)
		}
		easCACertPool.AppendCertsFromPEM(easStore.CACertBytes())
	}

	cfg := server.Config{
		Address:     "127.0.0.1:8443",
		CACertFiles: []string{store.CertFile("ca")},
		CertFile:    store.CertFile("tls"),
		KeyFile:     store.KeyFile("tls"),
	}

	srv := server.NewGenericServer(cfg)

	r := mux.NewRouter()
	r.HandleFunc("/apiserver/{resource}", func(writer http.ResponseWriter, request *http.Request) {
		vars := mux.Vars(request)
		writer.WriteHeader(http.StatusOK)
		fmt.Fprintf(writer, "resource: %v", vars["resource"])
	})

	r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "OK")
	})

	// HandleFunc for proxying the request to eas
	if proxy {
		r.HandleFunc("/extended/{resource}", func(writer http.ResponseWriter, request *http.Request) {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{rhCert},
					RootCAs:      easCACertPool,
				},
				MaxIdleConnsPerHost: 10,
			}
			client := http.Client{
				Transport: tr,
				Timeout:   time.Duration(time.Minute * 30),
			}
			u := *request.URL
			u.Scheme = "https"
			u.Host = "127.0.0.2:8443"
			fmt.Println("forwarding request to", u.String())

			req, err := http.NewRequest(request.Method, u.String(), nil)
			if err != nil {
				log.Fatalln("error here", err)
			}

			// If external client exist or this server is a proxy server. Setting that external client
			// profile to auth from eas
			if len(request.TLS.PeerCertificates) > 0 {
				req.Header.Set("X-Remote-User", request.TLS.PeerCertificates[0].Subject.CommonName)
			}

			resp, err := client.Do(req)
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				log.Fatalln(err)
				return
			}
			defer resp.Body.Close()

			writer.WriteHeader(http.StatusOK)
			io.Copy(writer, resp.Body)
		})
	}

	srv.ListenAndServe(r)
}
