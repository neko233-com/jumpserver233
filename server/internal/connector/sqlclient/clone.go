package sqlclient

// CloneResult gives each consumer its own mutable rows and optional metadata.
func CloneResult(r Result) Result {
	r.MissingCells = append([][2]int(nil), r.MissingCells...)
	r.Columns = append([]Column(nil), r.Columns...)
	if r.ResultSets != nil {
		sets := make([]ResultSet, len(r.ResultSets))
		for i, set := range r.ResultSets {
			copy := CloneResult(Result{Columns: set.Columns, Rows: set.Rows})
			sets[i] = ResultSet{Columns: copy.Columns, Rows: copy.Rows}
		}
		r.ResultSets = sets
	}
	if r.Rows != nil {
		rows := make([][]*string, len(r.Rows))
		for i, row := range r.Rows {
			rows[i] = make([]*string, len(row))
			for j, cell := range row {
				if cell != nil {
					value := *cell
					rows[i][j] = &value
				}
			}
		}
		r.Rows = rows
	}
	if r.AffectedRowsKnown != nil {
		known := *r.AffectedRowsKnown
		r.AffectedRowsKnown = &known
	}
	return r
}
