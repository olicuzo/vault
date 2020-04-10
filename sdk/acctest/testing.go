// Package acctest is for acceptance testing
package acctest

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest/docker"
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
