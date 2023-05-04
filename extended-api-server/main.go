package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sayedppqq/extended-server-connection/lib/certstore"
	"github.com/sayedppqq/extended-server-connection/lib/server"
	"github.com/spf13/afero"
	"k8s.io/client-go/util/cert"
	"log"
	"net"
	"net/http"
)

func main() {
	var proxy = false
	flag.BoolVar(&proxy, "receive-proxy-request", proxy, "receive forward request from api-server")
	flag.Parse()

	fs := afero.NewOsFs()
	store, err := certstore.NewCertStore(fs, "/tmp/extended-server-connection")
	if err != nil {
		log.Fatalln(err)
	}
	err = store.NewCA("extended")
	if err != nil {
		log.Fatalln(err)
	}

	serverCert, serverKey, err := store.NewServerCertPair(cert.AltNames{
		IPs: []net.IP{net.ParseIP("127.0.0.2")},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.Write("tls", serverCert, serverKey)

	clientCert, clientKey, err := store.NewClientCertPair(cert.AltNames{
		DNSNames: []string{"jane"},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.Write("jane", clientCert, clientKey)
	if err != nil {
		log.Fatalln(err)
	}

	apiserverStore, err := certstore.NewCertStore(fs, "/tmp/extended-server-connection")
	if err != nil {
		log.Fatalln(err)
	}
	if proxy {
		err = apiserverStore.LoadCA("apiserver")
		if err != nil {
			log.Fatalln(err)
		}
	}

	rhCACertPool := x509.NewCertPool()
	rhStore, err := certstore.NewCertStore(fs, "/tmp/extended-server-connection")
	if err != nil {
		log.Fatalln(err)
	}
	if proxy {
		err = rhStore.LoadCA("requestheader")
		if err != nil {
			log.Fatalln(err)
		}
		rhCACertPool.AppendCertsFromPEM(rhStore.CACertBytes())
	}

	cfg := server.Config{
		Address:     "127.0.0.2:8443",
		CACertFiles: []string{},
		CertFile:    store.CertFile("tls"),
		KeyFile:     store.KeyFile("tls"),
	}
	if proxy {
		cfg.CACertFiles = append(cfg.CACertFiles, apiserverStore.CertFile("ca"))
		cfg.CACertFiles = append(cfg.CACertFiles, rhStore.CertFile("ca"))
	}

	srv := server.NewGenericServer(cfg)

	r := mux.NewRouter()
	r.HandleFunc("/extended/{resource}", func(writer http.ResponseWriter, request *http.Request) {
		user := "system"
		src := "-"
		if len(request.TLS.PeerCertificates) > 0 {
			option := x509.VerifyOptions{
				Roots:     rhCACertPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, err := request.TLS.PeerCertificates[0].Verify(option); err != nil {
				user = request.TLS.PeerCertificates[0].Subject.CommonName
				src = "Client-Cert-CN"
			} else {
				user = request.Header.Get("X-Remote-User")
				src = "X-Remote-User"
			}
		}

		vars := mux.Vars(request)
		writer.WriteHeader(http.StatusOK)
		fmt.Fprintf(writer, "resource: %v request by user[%s] = %s", vars["resource"], user, src)
	})

	r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "OK")
	})

	srv.ListenAndServe(r)
}
