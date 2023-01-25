package generator

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/mozillazg/pkiutil/pkg/encoder"
	"github.com/stretchr/testify/assert"
)

func TestGenCACert(t *testing.T) {
	opt := CertOption{
		CommonName:    "test",
		Organizations: []string{"test"},
		Hosts:         []string{"example.com"},
		NotBefore:     time.Now(),
		NotAfter:      time.Now().Add(time.Minute),
	}
	cert, key, err := GenCACert(opt)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.NotNil(t, key)
	assert.Equal(t, cert.Subject.CommonName, opt.CommonName)
	assert.Equal(t, cert.Subject.Organization, opt.Organizations)
	assert.Equal(t, cert.DNSNames, opt.Hosts)
	assert.Equal(t, cert.NotBefore.UTC().Format(time.RFC822Z), opt.NotBefore.UTC().Format(time.RFC822Z))
	assert.Equal(t, cert.NotAfter.UTC().Format(time.RFC822Z), opt.NotAfter.UTC().Format(time.RFC822Z))

	assert.True(t, cert.IsCA)
	assert.Equal(t, cert.KeyUsage, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageCertSign)
	assert.Equal(t, 0, len(cert.ExtKeyUsage))
}

func TestGenServerCert(t *testing.T) {
	opt := CertOption{
		CommonName:    "test",
		Organizations: []string{"test"},
		Hosts:         []string{"example.com"},
		NotBefore:     time.Now(),
		NotAfter:      time.Now().Add(time.Minute),
	}
	cert, key, err := GenServerCert(opt)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.NotNil(t, key)
	assert.Equal(t, cert.Subject.CommonName, opt.CommonName)
	assert.Equal(t, cert.Subject.Organization, opt.Organizations)
	assert.Equal(t, cert.DNSNames, opt.Hosts)
	assert.Equal(t, cert.NotBefore.UTC().Format(time.RFC822Z), opt.NotBefore.UTC().Format(time.RFC822Z))
	assert.Equal(t, cert.NotAfter.UTC().Format(time.RFC822Z), opt.NotAfter.UTC().Format(time.RFC822Z))

	assert.False(t, cert.IsCA)
	assert.Equal(t, cert.KeyUsage, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
	assert.Equal(t, cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func TestGenClientCert(t *testing.T) {
	opt := CertOption{
		CommonName:    "test",
		Organizations: []string{"test"},
		Hosts:         []string{"example.com"},
		NotBefore:     time.Now(),
		NotAfter:      time.Now().Add(time.Minute),
	}
	cert, key, err := GenClientCert(opt)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.NotNil(t, key)
	assert.Equal(t, cert.Subject.CommonName, opt.CommonName)
	assert.Equal(t, cert.Subject.Organization, opt.Organizations)
	assert.Equal(t, cert.DNSNames, opt.Hosts)
	assert.Equal(t, cert.NotBefore.UTC().Format(time.RFC822Z), opt.NotBefore.UTC().Format(time.RFC822Z))
	assert.Equal(t, cert.NotAfter.UTC().Format(time.RFC822Z), opt.NotAfter.UTC().Format(time.RFC822Z))

	assert.False(t, cert.IsCA)
	assert.Equal(t, cert.KeyUsage, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
	assert.Equal(t, cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

func Test_genCertWithIpAndExtra(t *testing.T) {
	opt := certOption{
		CertOption: CertOption{
			Hosts:     []string{"example.com", "127.0.0.1", "abc.com", "192.168.0.1"},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Minute),
			ExtraSubject: pkix.Name{
				CommonName:   "test",
				Organization: []string{"test"},
			},
		},
		isCA:     false,
		isServer: true,
	}
	cert, key, err := genCert(opt)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.NotNil(t, key)

	dnsNames := cert.DNSNames
	ips := []string{}
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	assert.Equal(t, cert.Subject.CommonName, opt.ExtraSubject.CommonName)
	assert.Equal(t, cert.Subject.Organization, opt.ExtraSubject.Organization)
	assert.Equal(t, []string{"example.com", "abc.com"}, dnsNames)
	assert.Equal(t, []string{"127.0.0.1", "192.168.0.1"}, ips)
	assert.Equal(t, cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func Test_genCertWithExtraKeyUsage(t *testing.T) {
	opt := certOption{
		CertOption: CertOption{
			Hosts:     []string{"example.com", "127.0.0.1", "abc.com", "192.168.0.1"},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Minute),
			ExtraSubject: pkix.Name{
				CommonName:   "test",
				Organization: []string{"test"},
			},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection},
		},
		isCA:     false,
		isServer: true,
	}
	cert, key, err := genCert(opt)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.NotNil(t, key)

	assert.Equal(t, cert.Subject.CommonName, opt.ExtraSubject.CommonName)
	assert.Equal(t, cert.Subject.Organization, opt.ExtraSubject.Organization)
	assert.Equal(t, cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning,
		x509.ExtKeyUsageEmailProtection})
}

type CertFiles struct {
	CaCert         *x509.Certificate
	CaCertPath     string
	CaKey          *rsa.PrivateKey
	CaKeyPath      string
	ServerCert     *x509.Certificate
	ServerCertPath string
	ServerKey      *rsa.PrivateKey
	ServerKeyPath  string
	ClientCert     *x509.Certificate
	ClientCertPath string
	ClientKey      *rsa.PrivateKey
	ClientKeyPath  string
	BaseDir        string
}

func genCertForTesting(t *testing.T) CertFiles {
	caCert, caKey, err := GenCACert(CertOption{
		CommonName:    "ca",
		Organizations: []string{"abc inc"},
	})
	assert.NoError(t, err)
	assert.NotNil(t, caCert)
	assert.NotNil(t, caKey)
	baseDir, err := os.MkdirTemp("", "pkiutil-test-cert-")
	t.Logf("temp dir: %s", baseDir)
	assert.NoError(t, err)
	ret := CertFiles{
		BaseDir: baseDir,
		CaCert:  caCert,
		CaKey:   caKey,
	}
	caCertPem, _ := encoder.PemEncodeCert(caCert)
	caKeyPem, _ := encoder.PemEncodePrivateKey(caKey)
	f := path.Join(baseDir, "ca_cert.pem")
	err = ioutil.WriteFile(f, caCertPem, 0644)
	assert.NoError(t, err)
	ret.CaCertPath = f
	f = path.Join(baseDir, "ca_key.pem")
	err = ioutil.WriteFile(f, caKeyPem, 0644)
	assert.NoError(t, err)
	ret.CaKeyPath = f

	serverCert, serverKey, err := GenServerCert(CertOption{
		CommonName:    "server-name",
		Organizations: []string{"abc inc"},
		Hosts:         []string{"example.svc", "localhost"},
		ParentCert:    caCert,
		ParentKey:     caKey,
	})
	assert.NoError(t, err)
	assert.NotNil(t, serverCert)
	assert.NotNil(t, serverKey)
	ret.ServerCert = serverCert
	ret.ServerKey = serverKey
	serverCertPem, _ := encoder.PemEncodeCert(serverCert)
	serverKeyPem, _ := encoder.PemEncodePrivateKey(serverKey)
	f = path.Join(baseDir, "server_cert.pem")
	err = ioutil.WriteFile(f, serverCertPem, 0644)
	assert.NoError(t, err)
	ret.ServerCertPath = f
	f = path.Join(baseDir, "server_key.pem")
	err = ioutil.WriteFile(f, serverKeyPem, 0644)
	assert.NoError(t, err)
	ret.ServerKeyPath = f

	clientCert, clientKey, err := GenClientCert(CertOption{
		CommonName:    "client-name",
		Organizations: []string{"abc inc"},
		ParentCert:    caCert,
		ParentKey:     caKey,
	})
	assert.NoError(t, err)
	assert.NotNil(t, clientCert)
	assert.NotNil(t, clientKey)
	ret.ClientCert = clientCert
	ret.ClientKey = clientKey
	clientCertPem, _ := encoder.PemEncodeCert(clientCert)
	clientKeyPem, _ := encoder.PemEncodePrivateKey(clientKey)
	f = path.Join(baseDir, "client_cert.pem")
	err = ioutil.WriteFile(f, clientCertPem, 0644)
	assert.NoError(t, err)
	ret.ClientCertPath = f
	f = path.Join(baseDir, "client_key.pem")
	err = ioutil.WriteFile(f, clientKeyPem, 0644)
	assert.NoError(t, err)
	ret.ClientKeyPath = f

	return ret
}

func Test_user_generated_cert_as_server_and_client_cert_without_client_auth(t *testing.T) {
	certs := genCertForTesting(t)
	lister, _ := net.Listen("tcp", "127.0.0.1:")
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})

	go func() {
		err := http.ServeTLS(lister, mux, certs.ServerCertPath, certs.ServerKeyPath)
		if err != nil && err != http.ErrServerClosed {
			assert.NoError(t, err)
		}
	}()

	caCert, _ := ioutil.ReadFile(certs.CaCertPath)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	clientCert, _ := tls.LoadX509KeyPair(certs.ClientCertPath, certs.ClientKeyPath)
	ts := http.DefaultTransport.(*http.Transport).Clone()
	tlsWithCert := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{clientCert},
	}
	tlsSkipCert := &tls.Config{InsecureSkipVerify: true}
	client := http.Client{
		Transport: ts,
	}

	addr := strings.Replace(lister.Addr().String(), "127.0.0.1", "localhost", 1)
	url := fmt.Sprintf("https://%s/hello", addr)
	_, err := http.Get(url)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown authority")

	ts.TLSClientConfig = tlsSkipCert
	_, err = client.Get(url)
	assert.NoError(t, err)

	ts.TLSClientConfig = tlsWithCert
	resp, err := client.Get(url)
	assert.NoError(t, err)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	assert.Equal(t, "hello", string(body))

}

func Test_user_generated_cert_as_server_and_client_cert_with_client_auth(t *testing.T) {
	certs := genCertForTesting(t)
	lister, _ := net.Listen("tcp", "127.0.0.1:")
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})

	caCert, _ := ioutil.ReadFile(certs.CaCertPath)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	serverCert, _ := tls.LoadX509KeyPair(certs.ServerCertPath, certs.ServerKeyPath)

	go func() {
		srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caCertPool,
		}}
		err := srv.ServeTLS(lister, "", "")
		if err != nil && err != http.ErrServerClosed {
			assert.NoError(t, err)
		}
	}()

	clientCert, _ := tls.LoadX509KeyPair(certs.ClientCertPath, certs.ClientKeyPath)
	ts := http.DefaultTransport.(*http.Transport).Clone()
	tlsWithCert := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{clientCert},
	}
	tlsSkipCert := &tls.Config{InsecureSkipVerify: true}
	client := http.Client{
		Transport: ts,
	}

	addr := strings.Replace(lister.Addr().String(), "127.0.0.1", "localhost", 1)
	url := fmt.Sprintf("https://%s/hello", addr)
	_, err := http.Get(url)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown authority")

	ts.TLSClientConfig = tlsSkipCert
	_, err = client.Get(url)
	assert.Error(t, err)

	ts.TLSClientConfig = tlsWithCert
	resp, err := client.Get(url)
	assert.NoError(t, err)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	assert.Equal(t, "hello", string(body))
}

func Test_genCert_with_parent_key_still_gen_private_key(t *testing.T) {
	certs := genCertForTesting(t)
	assert.False(t, certs.CaKey.Equal(certs.ServerKey))
	assert.False(t, certs.CaKey.Equal(certs.ClientKey))
	assert.False(t, certs.ServerKey.Equal(certs.ClientKey))
}
