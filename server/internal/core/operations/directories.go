package operations

import "github.com/neko233-com/jumpserver233/server/internal/hostagent"

func validOperationDirectory(directory string, management bool) bool {
	return directory == "" || !management && hostagent.ValidateWorkspace(directory) == nil
}

// Version five authenticates directory snapshots. Older envelopes cannot opt in
// to new execution semantics by adding an otherwise unknown JSON property.
func validateOperationDirectories(st state, version int) error {
	valid := func(directory string, management bool) bool {
		return validOperationDirectory(directory, management) && (directory == "" || version >= 5)
	}
	for _, t := range st.Templates {
		if !valid(t.WorkingDirectory, false) {
			return ErrInvalid
		}
	}
	for _, p := range st.Plans {
		if !valid(p.WorkingDirectory, p.HostPlugin != nil || p.Discovery != nil) {
			return ErrInvalid
		}
	}
	for _, r := range st.Runs {
		if !valid(r.WorkingDirectory, r.HostPlugin != nil || r.Discovery != nil) {
			return ErrInvalid
		}
	}
	return nil
}
