package assets

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
)

const ProtocolKubernetes = "kubernetes"

func IsKubernetes(a Asset) bool { return Protocol(a) == ProtocolKubernetes }
func (s *Service) kubernetesConnection(id string) (Asset, kubeclient.Target, string, error) {
	a, t, c, e := s.store.connectionForProtocol(id, false)
	if e != nil {
		return Asset{}, kubeclient.Target{}, "", e
	}
	if !IsKubernetes(a) || a.Kubernetes == nil {
		return Asset{}, kubeclient.Target{}, "", ErrUnsupportedProtocol
	}
	return a, kubeclient.Target{Host: a.Host, Port: a.Port, Settings: *a.Kubernetes, Gateways: t.Gateways}, c.Password, nil
}
func (s *Service) KubernetesPods(ctx context.Context, id, namespace string) ([]kubeclient.Pod, error) {
	_, t, token, e := s.kubernetesConnection(id)
	if e != nil {
		return nil, e
	}
	return kubeclient.ListPods(ctx, t, token, namespace)
}
func (s *Service) OpenKubernetesShell(ctx context.Context, id string, v kubeclient.Selection, cols, rows int) (Asset, *kubeclient.Shell, error) {
	a, t, token, e := s.kubernetesConnection(id)
	if e != nil {
		return Asset{}, nil, e
	}
	shell, e := kubeclient.OpenShell(ctx, t, token, v, cols, rows)
	return a, shell, e
}
