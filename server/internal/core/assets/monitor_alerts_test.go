package assets

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func TestMonitorProjectionBindsObservationToTargetAndOmitsSecrets(t *testing.T) {
	store, e := OpenStore(filepath.Join(t.TempDir(), "a"), make([]byte, 32))
	require.NoError(t, e)
	service := NewService(store, func(context.Context, sshclient.Target, sshclient.Credentials, time.Duration) (sshclient.Metrics, error) {
		return sshclient.Metrics{CPUPercent: 12, NetworkReceivedBytes: 100, NetworkSentBytes: 200}, nil
	})
	in := Input{Name: "Synthetic host", Host: "192.0.2.1", Port: 22, Username: "ops", Password: "synthetic-private-password", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	a, e := service.Create(in)
	require.NoError(t, e)
	_, e = service.Probe(context.Background(), a.ID)
	require.NoError(t, e)
	source := service.MonitorSources(nil)[0]
	assert.Equal(t, "online", source.State)
	assert.Equal(t, 12.0, source.Values["cpu_percent"])
	assert.NotContains(t, source.Values, "memory_percent")
	assert.NotContains(t, source.Values, "network_rx_bps")
	raw, e := json.Marshal(source)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), in.Password)
	assert.NotContains(t, string(raw), in.Host)
	assert.NotContains(t, string(raw), "ops")
	// A late result for an old endpoint cannot be used for the replacement.
	in.Host = "192.0.2.2"
	in.Password = ""
	a, e = service.Update(a.ID, in)
	require.NoError(t, e)
	changed := service.MonitorSources(nil)[0]
	assert.NotEqual(t, source.Binding, changed.Binding)
	assert.Equal(t, "unknown", changed.State)
	assert.True(t, changed.At.IsZero())
	_, e = service.Probe(context.Background(), a.ID)
	require.NoError(t, e)
	assert.Equal(t, "online", service.MonitorSources(nil)[0].State)
	// Credential rotation and a display rename preserve the target identity.
	current := service.MonitorSources(nil)[0]
	in.Password = "synthetic-replacement-password"
	in.Name = "Renamed synthetic host"
	_, e = service.Update(a.ID, in)
	require.NoError(t, e)
	assert.Equal(t, current.Binding, service.MonitorSources(nil)[0].Binding)
}
func TestMonitorNetworkRatesRequireTwoSamplesFromSameBinding(t *testing.T) {
	store, e := OpenStore(filepath.Join(t.TempDir(), "a"), make([]byte, 32))
	require.NoError(t, e)
	s := NewService(store, nil)
	a, e := s.Create(Input{Name: "Synthetic host", Host: "192.0.2.1", Port: 22, Username: "ops", Password: "synthetic-private-password", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	require.NoError(t, e)
	binding := s.MonitorSources(nil)[0].Binding
	at := time.Now().UTC()
	m := sshclient.Metrics{NetworkReceivedBytes: 100, NetworkSentBytes: 100}
	s.recordMetrics(a.ID, m, at, binding)
	m.NetworkReceivedBytes = 300
	m.NetworkSentBytes = 500
	s.recordMetrics(a.ID, m, at.Add(2*time.Second), binding)
	assert.Equal(t, 100.0, s.MonitorSources(nil)[0].Values["network_rx_bps"])
	// Counter reset is unknown rather than fabricated zero traffic.
	m.NetworkReceivedBytes = 1
	m.NetworkSentBytes = 1
	s.recordMetrics(a.ID, m, at.Add(4*time.Second), binding)
	assert.NotContains(t, s.MonitorSources(nil)[0].Values, "network_rx_bps")
	m.NetworkReceivedBytes = 1000
	m.NetworkSentBytes = 1000
	status := s.recordMetrics(a.ID, m, at.Add(6*time.Second), "different-binding")
	assert.False(t, status.networkReady)
	assert.Equal(t, "unknown", s.MonitorSources(nil)[0].State)
}
