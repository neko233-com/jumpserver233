package assets

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxAccountImportBytes = 10 << 20
const MaxAccountImportRows = 500

var ErrAccountImportFormat = errors.New("invalid account import document")
var errAccountImportRowLimit = errors.New("account import row limit")
var accountImportHeaders = []string{"action", "asset_id", "username", "name", "remark", "credential_type", "password", "private_key", "private_key_passphrase", "active", "password_rotation_enabled", "key_rotation_enabled", "version"}

// Import rows are write-only inputs. Errors never include cell contents.
type AccountImportRow struct {
	Line    int          `json:"line"`
	AssetID string       `json:"asset_id"`
	Action  string       `json:"action"`
	Input   AccountInput `json:"input"`
}
type AccountImportIssue struct {
	Line  int    `json:"line"`
	Field string `json:"field,omitempty"`
	Code  string `json:"code"`
}
type importCells struct {
	line   int
	values []string
}

func ParseAccountImport(format string, raw []byte) ([]AccountImportRow, []AccountImportIssue) {
	if len(raw) == 0 || len(raw) > MaxAccountImportBytes {
		return nil, []AccountImportIssue{{Code: "file_size"}}
	}
	var cells []importCells
	var err error
	switch format {
	case "csv":
		cells, err = readAccountCSV(raw)
	case "xlsx":
		cells, err = readAccountXLSX(raw)
	default:
		err = ErrAccountImportFormat
	}
	if errors.Is(err, errAccountImportRowLimit) {
		return nil, []AccountImportIssue{{Code: "row_limit"}}
	}
	if err != nil || len(cells) < 2 {
		return nil, []AccountImportIssue{{Code: "file_format"}}
	}
	headers := map[string]int{}
	known := map[string]bool{}
	for _, name := range accountImportHeaders {
		known[name] = true
	}
	for i, name := range cells[0].values {
		name = strings.TrimSpace(strings.TrimPrefix(name, "\ufeff"))
		if !known[name] {
			return nil, []AccountImportIssue{{Line: cells[0].line, Code: "headers"}}
		}
		if _, ok := headers[name]; ok {
			return nil, []AccountImportIssue{{Line: cells[0].line, Code: "headers"}}
		}
		headers[name] = i
	}
	for _, name := range []string{"action", "asset_id", "username"} {
		if _, ok := headers[name]; !ok {
			return nil, []AccountImportIssue{{Line: cells[0].line, Field: name, Code: "headers"}}
		}
	}
	rows := make([]AccountImportRow, 0, len(cells)-1)
	issues := []AccountImportIssue{}
	for _, cell := range cells[1:] {
		if len(cell.values) > len(cells[0].values) {
			for _, extra := range cell.values[len(cells[0].values):] {
				if extra != "" {
					return nil, []AccountImportIssue{{Line: cell.line, Code: "headers"}}
				}
			}
		}
		if len(rows) >= MaxAccountImportRows {
			return nil, []AccountImportIssue{{Code: "row_limit"}}
		}
		get := func(name string) string {
			i, ok := headers[name]
			if !ok || i >= len(cell.values) {
				return ""
			}
			return cell.values[i]
		}
		row := AccountImportRow{Line: cell.line, AssetID: strings.TrimSpace(get("asset_id")), Action: strings.TrimSpace(get("action")), Input: AccountInput{Username: strings.TrimSpace(get("username")), CredentialType: strings.TrimSpace(get("credential_type")), Password: get("password"), PrivateKey: get("private_key"), PrivateKeyPassphrase: get("private_key_passphrase"), Version: strings.TrimSpace(get("version"))}}
		for name, dst := range map[string]**string{"name": &row.Input.Name, "remark": &row.Input.Remark} {
			if value := get(name); value != "" {
				*dst = &value
			}
		}
		for name, dst := range map[string]**bool{"active": &row.Input.Active, "password_rotation_enabled": &row.Input.PasswordRotationEnabled, "key_rotation_enabled": &row.Input.KeyRotationEnabled} {
			value := strings.TrimSpace(get(name))
			if value == "" {
				continue
			}
			if value != "true" && value != "false" {
				issues = append(issues, AccountImportIssue{Line: cell.line, Field: name, Code: "boolean"})
				continue
			}
			v := value == "true"
			*dst = &v
		}
		rows = append(rows, row)
	}
	return rows, issues
}

func readAccountCSV(raw []byte) ([]importCells, error) {
	if !utf8.Valid(raw) {
		return nil, ErrAccountImportFormat
	}
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})))
	r.ReuseRecord = false
	rows := []importCells{}
	for {
		v, e := r.Read()
		if e == io.EOF {
			break
		}
		if e != nil || len(v) > len(accountImportHeaders) {
			return nil, ErrAccountImportFormat
		}
		if len(rows) > MaxAccountImportRows {
			return nil, errAccountImportRowLimit
		}
		line, _ := r.FieldPos(0)
		rows = append(rows, importCells{line, v})
	}
	return rows, nil
}

type importXMLText struct {
	Text string `xml:"t"`
	Runs []struct {
		Text string `xml:"t"`
	} `xml:"r"`
}

func (v importXMLText) text() string {
	var b strings.Builder
	b.WriteString(v.Text)
	for _, r := range v.Runs {
		b.WriteString(r.Text)
	}
	return b.String()
}
func decodeImportXML(raw []byte, out any) error {
	if !utf8.Valid(raw) {
		return ErrAccountImportFormat
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	depth, tokens := 0, 0
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return ErrAccountImportFormat
		}
		switch v := t.(type) {
		case xml.Directive:
			return ErrAccountImportFormat
		case xml.StartElement:
			depth++
			if depth > 64 {
				return ErrAccountImportFormat
			}
			if v.Name.Local == "f" {
				return ErrAccountImportFormat
			}
		case xml.EndElement:
			depth--
		}
		tokens++
		if tokens > 1_000_000 {
			return ErrAccountImportFormat
		}
	}
	if xml.Unmarshal(raw, out) != nil {
		return ErrAccountImportFormat
	}
	return nil
}
func readAccountXLSX(raw []byte) ([]importCells, error) {
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil || len(z.File) > 256 {
		return nil, ErrAccountImportFormat
	}
	files := map[string]*zip.File{}
	seen := map[string]bool{}
	var size uint64
	for _, f := range z.File {
		name := strings.TrimSuffix(f.Name, "/")
		lower := strings.ToLower(name)
		if name == "" || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00") || seen[lower] || strings.HasPrefix(lower, "../") || strings.HasSuffix(lower, ".bin") || strings.Contains(lower, "externallinks/") {
			return nil, ErrAccountImportFormat
		}
		seen[lower] = true
		if f.UncompressedSize64 > (32<<20)-size {
			return nil, ErrAccountImportFormat
		}
		size += f.UncompressedSize64
		files[f.Name] = f
	}
	read := func(name string) ([]byte, error) {
		f := files[name]
		if f == nil || f.UncompressedSize64 > 16<<20 {
			return nil, ErrAccountImportFormat
		}
		r, e := f.Open()
		if e != nil {
			return nil, ErrAccountImportFormat
		}
		defer r.Close()
		data, e := io.ReadAll(io.LimitReader(r, (16<<20)+1))
		if e != nil || len(data) > 16<<20 {
			return nil, ErrAccountImportFormat
		}
		return data, nil
	}
	for name := range files {
		if strings.HasSuffix(strings.ToLower(name), ".rels") {
			data, e := read(name)
			if e != nil {
				return nil, ErrAccountImportFormat
			}
			var links struct {
				Items []struct {
					Mode   string `xml:"TargetMode,attr"`
					Target string `xml:"Target,attr"`
				} `xml:"Relationship"`
			}
			if decodeImportXML(data, &links) != nil {
				return nil, ErrAccountImportFormat
			}
			for _, link := range links.Items {
				if strings.EqualFold(link.Mode, "External") || strings.Contains(link.Target, ":") || strings.HasPrefix(link.Target, "//") {
					return nil, ErrAccountImportFormat
				}
			}
		}
	}
	var book struct {
		Sheets []struct {
			ID    string `xml:"id,attr"`
			State string `xml:"state,attr"`
		} `xml:"sheets>sheet"`
	}
	data, e := read("xl/workbook.xml")
	if e != nil || decodeImportXML(data, &book) != nil || len(book.Sheets) != 1 || book.Sheets[0].ID == "" || book.Sheets[0].State != "" && book.Sheets[0].State != "visible" {
		return nil, ErrAccountImportFormat
	}
	var rels struct {
		Items []struct {
			ID     string `xml:"Id,attr"`
			Target string `xml:"Target,attr"`
			Mode   string `xml:"TargetMode,attr"`
			Type   string `xml:"Type,attr"`
		} `xml:"Relationship"`
	}
	data, e = read("xl/_rels/workbook.xml.rels")
	if e != nil || decodeImportXML(data, &rels) != nil {
		return nil, ErrAccountImportFormat
	}
	sheetPath := ""
	for _, r := range rels.Items {
		if r.Mode == "External" {
			return nil, ErrAccountImportFormat
		}
		if r.ID == book.Sheets[0].ID {
			if sheetPath != "" || !strings.HasSuffix(r.Type, "/worksheet") {
				return nil, ErrAccountImportFormat
			}
			sheetPath = path.Join("xl", r.Target)
			if strings.HasPrefix(r.Target, "/xl/") {
				sheetPath = strings.TrimPrefix(r.Target, "/")
			}
		}
	}
	if !strings.HasPrefix(sheetPath, "xl/worksheets/") || path.Clean(sheetPath) != sheetPath {
		return nil, ErrAccountImportFormat
	}
	var shared struct {
		Items []importXMLText `xml:"si"`
	}
	if files["xl/sharedStrings.xml"] != nil {
		data, e = read("xl/sharedStrings.xml")
		if e != nil || decodeImportXML(data, &shared) != nil || len(shared.Items) > 100_000 {
			return nil, ErrAccountImportFormat
		}
	}
	var sheet struct {
		Rows []struct {
			Index int `xml:"r,attr"`
			Cells []struct {
				Ref    string        `xml:"r,attr"`
				Type   string        `xml:"t,attr"`
				Value  string        `xml:"v"`
				Inline importXMLText `xml:"is"`
			} `xml:"c"`
		} `xml:"sheetData>row"`
	}
	data, e = read(sheetPath)
	if e != nil || decodeImportXML(data, &sheet) != nil {
		return nil, ErrAccountImportFormat
	}
	rows := []importCells{}
	previous := 0
	for _, row := range sheet.Rows {
		if row.Index <= previous || row.Index > 1_048_576 || len(row.Cells) > len(accountImportHeaders) {
			return nil, ErrAccountImportFormat
		}
		previous = row.Index
		values := make([]string, len(accountImportHeaders))
		used := map[int]bool{}
		for _, c := range row.Cells {
			col, index, e := importCellReference(c.Ref)
			if e != nil || index != row.Index || col >= len(values) || used[col] {
				return nil, ErrAccountImportFormat
			}
			used[col] = true
			value := c.Value
			switch c.Type {
			case "inlineStr":
				value = c.Inline.text()
			case "s":
				i, e := strconv.Atoi(value)
				if e != nil || i < 0 || i >= len(shared.Items) {
					return nil, ErrAccountImportFormat
				}
				value = shared.Items[i].text()
			case "b":
				if value == "1" {
					value = "true"
				} else if value == "0" {
					value = "false"
				} else {
					return nil, ErrAccountImportFormat
				}
			case "", "n", "str":
			default:
				return nil, ErrAccountImportFormat
			}
			values[col] = value
		}
		empty := true
		for _, value := range values {
			if value != "" {
				empty = false
				break
			}
		}
		if empty {
			continue
		}
		if len(rows) >= MaxAccountImportRows+1 {
			return nil, errAccountImportRowLimit
		}
		if len(rows) == 0 {
			last := len(values)
			for last > 0 && values[last-1] == "" {
				last--
			}
			values = values[:last]
		}
		rows = append(rows, importCells{row.Index, values})
	}
	return rows, nil
}
func importCellReference(s string) (int, int, error) {
	col, i := 0, 0
	for i < len(s) && s[i] >= 'A' && s[i] <= 'Z' {
		col = col*26 + int(s[i]-'A') + 1
		i++
		if col > len(accountImportHeaders) {
			return 0, 0, ErrAccountImportFormat
		}
	}
	row, e := strconv.Atoi(s[i:])
	if i == 0 || e != nil || row < 1 || strconv.Itoa(row) != s[i:] {
		return 0, 0, ErrAccountImportFormat
	}
	return col - 1, row, nil
}

// Templates contain only fixed headers and placeholders, never stored secrets.
func AccountImportTemplate(format string) ([]byte, error) {
	records := [][]string{accountImportHeaders, {"create", "ASSET_ID", "LOGIN_USER", "", "", "password", "", "", "", "true", "", "", ""}}
	return AccountImportFile(format, records)
}

// AccountImportFile encodes caller-supplied cells. It never reads Vault data.
func AccountImportFile(format string, records [][]string) ([]byte, error) {
	if len(records) < 1 || len(records) > MaxAccountImportRows+1 {
		return nil, ErrAccountImportFormat
	}
	size := 0
	for _, row := range records {
		if len(row) > len(accountImportHeaders) {
			return nil, ErrAccountImportFormat
		}
		for _, cell := range row {
			size += len(cell)
			if size > MaxAccountImportBytes || !utf8.ValidString(cell) {
				return nil, ErrAccountImportFormat
			}
		}
	}
	if format == "csv" {
		var b bytes.Buffer
		w := csv.NewWriter(&b)
		w.UseCRLF = true
		if e := w.WriteAll(records); e != nil {
			return nil, e
		}
		return b.Bytes(), nil
	}
	if format != "xlsx" {
		return nil, ErrAccountImportFormat
	}
	var sheet strings.Builder
	sheet.WriteString(`<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	for i, record := range records {
		fmt.Fprintf(&sheet, `<row r="%d">`, i+1)
		for col, value := range record {
			fmt.Fprintf(&sheet, `<c r="%c%d" t="inlineStr"><is><t xml:space="preserve">`, 'A'+col, i+1)
			_ = xml.EscapeText(&sheet, []byte(value))
			sheet.WriteString(`</t></is></c>`)
		}
		sheet.WriteString(`</row>`)
	}
	sheet.WriteString(`</sheetData></worksheet>`)
	entries := []struct{ name, body string }{
		{"[Content_Types].xml", `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`},
		{"xl/workbook.xml", `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Accounts" sheetId="1" r:id="rId1"/></sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`}, {"xl/worksheets/sheet1.xml", sheet.String()}}
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, entry := range entries {
		file, e := w.Create(entry.name)
		if e != nil {
			return nil, e
		}
		if _, e = file.Write([]byte(entry.body)); e != nil {
			return nil, e
		}
	}
	if e := w.Close(); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
