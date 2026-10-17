package accountdiscovery

import "github.com/neko233-com/jumpserver233/server/internal/core/agentevents"

func (s *Store) ArchiveCollection(src Source, name string, actor Actor, r agentevents.Receipt) error {
	if !validSource(src) || actor.ID == "" {
		return ErrInvalid
	}
	return s.collections.Archive(agentevents.Source{AssetID: src.AssetID, AssetName: name, Account: src.Account}, agentevents.Collector{ID: actor.ID, Name: actor.Name, JobID: r.JobID}, r)
}
func (s *Store) Collections(assetID string, before uint64, limit int) (agentevents.Page, error) {
	if !assetPattern.MatchString(assetID) {
		return agentevents.Page{}, ErrInvalid
	}
	return s.collections.List(before, limit, func(src agentevents.Source) bool { return src.AssetID == assetID }, "collection")
}
func (s *Store) LatestCollection(id string) (agentevents.Receipt, bool) {
	return s.collections.LatestReceipt(id)
}
