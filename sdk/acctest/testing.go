package acctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	mathrand "math/rand"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/internalshared/reloadutil"
	"github.com/ory/dockertest/docker"

	"github.com/hashicorp/vault/vault"
)

type DockerClusterOptions struct {
	KeepStandbysSealed bool
	RequireClientAuth  bool
	SkipInit           bool
	CACert             []byte
	NumCores           int
	TempDir            string
	// SetupFunc is called after the cluster is started.
	SetupFunc func(t testing.T, c *DockerCluster)
	CAKey     *ecdsa.PrivateKey
}

type DockerClusterNode struct {
	NodeID            string
	Address           *net.TCPAddr
	HostPort          string
	Client            *api.Client
	ServerCert        *x509.Certificate
	ServerCertBytes   []byte
	ServerCertPEM     []byte
	ServerCertPEMFile string
	ServerKey         *ecdsa.PrivateKey
	ServerKeyPEM      []byte
	ServerKeyPEMFile  string
	TLSConfig         *tls.Config
	WorkDir           string
	Cluster           *DockerCluster
	container         *types.ContainerJSON
	dockerAPI         *docker.Client
}

type DockerCluster struct {
	RaftStorage        bool
	ClientAuthRequired bool
	BarrierKeys        [][]byte
	RecoveryKeys       [][]byte
	CACertBytes        []byte
	CACertPEM          []byte
	CAKeyPEM           []byte
	CACertPEMFile      string
	ID                 string
	RootToken          string
	TempDir            string
	ClusterName        string
	RootCAs            *x509.CertPool
	CACert             *x509.Certificate
	CAKey              *ecdsa.PrivateKey
	CleanupFunc        func()
	SetupFunc          func()
	ClusterNodes       []*DockerClusterNode
}

func (rc *DockerCluster) GetBarrierOrRecoveryKeys() [][]byte {
	return rc.GetBarrierKeys()
}

func (rc *DockerCluster) GetCACertPEMFile() string {
	return rc.CACertPEMFile
}

func (rc *DockerCluster) ClusterID() string {
	return rc.ID
}

func (n *DockerClusterNode) Name() string {
	return n.Cluster.ClusterName + "-" + n.NodeID
}

func (n *DockerClusterNode) APIClient() *api.Client {
	return n.Client
}

type VaultClusterNode interface {
	Name() string
	APIClient() *api.Client
}

func (rc *DockerCluster) Nodes() []VaultClusterNode {
	ret := make([]VaultClusterNode, len(rc.ClusterNodes))
	for i, core := range rc.ClusterNodes {
		ret[i] = core
	}
	return ret
}

func (rc *DockerCluster) GetBarrierKeys() [][]byte {
	ret := make([][]byte, len(rc.BarrierKeys))
	for i, k := range rc.BarrierKeys {
		ret[i] = vault.TestKeyCopy(k)
	}
	return ret
}

func (rc *DockerCluster) GetRecoveryKeys() [][]byte {
	ret := make([][]byte, len(rc.RecoveryKeys))
	for i, k := range rc.RecoveryKeys {
		ret[i] = vault.TestKeyCopy(k)
	}
	return ret
}

func (rc *DockerCluster) SetBarrierKeys(keys [][]byte) {
	rc.BarrierKeys = make([][]byte, len(keys))
	for i, k := range keys {
		rc.BarrierKeys[i] = vault.TestKeyCopy(k)
	}
}

func (rc *DockerCluster) SetRecoveryKeys(keys [][]byte) {
	rc.RecoveryKeys = make([][]byte, len(keys))
	for i, k := range keys {
		rc.RecoveryKeys[i] = vault.TestKeyCopy(k)
	}
}

func (rc *DockerCluster) setupCA(opts *DockerClusterOptions) error {
	var err error

	certIPs := []net.IP{
		net.IPv6loopback,
		net.ParseIP("127.0.0.1"),
	}

	var caKey *ecdsa.PrivateKey
	if opts != nil && opts.CAKey != nil {
		caKey = opts.CAKey
	} else {
		caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
	}
	rc.CAKey = caKey

	var caBytes []byte
	if opts != nil && len(opts.CACert) > 0 {
		caBytes = opts.CACert
	} else {
		caCertTemplate := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "localhost",
			},
			DNSNames:              []string{"localhost"},
			IPAddresses:           certIPs,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			SerialNumber:          big.NewInt(mathrand.Int63()),
			NotBefore:             time.Now().Add(-30 * time.Second),
			NotAfter:              time.Now().Add(262980 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		caBytes, err = x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, caKey.Public(), caKey)
		if err != nil {
			return err
		}
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return err
	}
	rc.CACert = caCert
	rc.CACertBytes = caBytes

	rc.RootCAs = x509.NewCertPool()
	rc.RootCAs.AddCert(caCert)

	caCertPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}
	rc.CACertPEM = pem.EncodeToMemory(caCertPEMBlock)

	rc.CACertPEMFile = filepath.Join(rc.TempDir, "ca", "ca.pem")
	err = ioutil.WriteFile(rc.CACertPEMFile, rc.CACertPEM, 0755)
	if err != nil {
		return err
	}

	marshaledCAKey, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return err
	}
	caKeyPEMBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: marshaledCAKey,
	}
	rc.CAKeyPEM = pem.EncodeToMemory(caKeyPEMBlock)

	// We don't actually need this file, but it may be helpful for debugging.
	err = ioutil.WriteFile(filepath.Join(rc.TempDir, "ca", "ca_key.pem"), rc.CAKeyPEM, 0755)
	if err != nil {
		return err
	}

	return nil
}

// Don't call this until n.Address.IP is populated
func (n *DockerClusterNode) setupCert() error {
	var err error

	n.ServerKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: n.Name(),
		},
		// Include host.docker.internal for the sake of benchmark-vault running on MacOS/Windows.
		// This allows Prometheus running in docker to scrape the cluster for metrics.
		DNSNames:    []string{"localhost", "host.docker.internal", n.Name()},
		IPAddresses: []net.IP{net.IPv6loopback, net.ParseIP("127.0.0.1")}, // n.Address.IP,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		SerialNumber: big.NewInt(mathrand.Int63()),
		NotBefore:    time.Now().Add(-30 * time.Second),
		NotAfter:     time.Now().Add(262980 * time.Hour),
	}
	n.ServerCertBytes, err = x509.CreateCertificate(rand.Reader, certTemplate, n.Cluster.CACert, n.ServerKey.Public(), n.Cluster.CAKey)
	if err != nil {
		return err
	}
	n.ServerCert, err = x509.ParseCertificate(n.ServerCertBytes)
	if err != nil {
		return err
	}
	n.ServerCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: n.ServerCertBytes,
	})

	marshaledKey, err := x509.MarshalECPrivateKey(n.ServerKey)
	if err != nil {
		return err
	}
	n.ServerKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: marshaledKey,
	})

	n.ServerCertPEMFile = filepath.Join(n.WorkDir, "cert.pem")
	err = ioutil.WriteFile(n.ServerCertPEMFile, n.ServerCertPEM, 0755)
	if err != nil {
		return err
	}

	n.ServerKeyPEMFile = filepath.Join(n.WorkDir, "key.pem")
	err = ioutil.WriteFile(n.ServerKeyPEMFile, n.ServerKeyPEM, 0755)
	if err != nil {
		return err
	}

	tlsCert, err := tls.X509KeyPair(n.ServerCertPEM, n.ServerKeyPEM)
	if err != nil {
		return err
	}

	certGetter := reloadutil.NewCertificateGetter(n.ServerCertPEMFile, n.ServerKeyPEMFile, "")
	if err := certGetter.Reload(nil); err != nil {
		// TODO error handle or panic?
		panic(err)
	}
	tlsConfig := &tls.Config{
		Certificates:   []tls.Certificate{tlsCert},
		RootCAs:        n.Cluster.RootCAs,
		ClientCAs:      n.Cluster.RootCAs,
		ClientAuth:     tls.RequestClientCert,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: certGetter.GetCertificate,
	}
	tlsConfig.BuildNameToCertificate()
	if n.Cluster.ClientAuthRequired {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	n.TLSConfig = tlsConfig

	return nil
}
