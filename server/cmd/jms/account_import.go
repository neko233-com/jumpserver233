package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

const accountImportUsage = "jms account import-template --format csv|xlsx --out PATH | import-preview --file PATH [--request-id ID] | import-commit --file PATH --preview-file REVIEW.json | imports [--offset 0] [--limit 20] | import-show REQUEST_ID [--actor-id ID]"

func executeAccountImport(ctx context.Context, c *sessionclient.Client, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New(accountImportUsage)
	}
	f := flag.NewFlagSet("account-import", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	switch args[0] {
	case "imports":
		offset, limit := f.Int("offset", 0, ""), f.Int("limit", 20, "")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || *offset < 0 || *limit < 1 || *limit > 100 {
			return errors.New(accountImportUsage)
		}
		rows, total, e := c.AccountImportHistory(ctx, *offset, *limit)
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(map[string]any{"results": rows, "total": total})
	case "import-show":
		if len(args) < 2 {
			return errors.New(accountImportUsage)
		}
		actor := f.String("actor-id", "", "")
		if f.Parse(args[2:]) != nil || f.NArg() != 0 {
			return errors.New(accountImportUsage)
		}
		v, e := c.AccountImportReceipt(ctx, args[1], *actor)
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(v)
	case "import-template":
		format, out := f.String("format", "csv", ""), f.String("out", "", "")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || *out == "" || (*format != "csv" && *format != "xlsx") {
			return errors.New(accountImportUsage)
		}
		raw, e := c.AccountImportTemplate(ctx, *format)
		if e != nil {
			return e
		}
		file, e := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return errors.New("could not create template output; choose a new file")
		}
		_, e = file.Write(raw)
		ce := file.Close()
		if e != nil || ce != nil {
			return errors.New("could not save the template")
		}
		return json.NewEncoder(output).Encode(map[string]string{"state": "saved", "format": *format})
	case "import-preview", "import-commit":
		fileName, format := f.String("file", "", ""), f.String("format", "", "")
		requestID, review := f.String("request-id", "", ""), f.String("preview-file", "", "")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || *fileName == "" || args[0] == "import-commit" && (*review == "" || *requestID != "") {
			return errors.New(accountImportUsage)
		}
		if *format == "" {
			*format = strings.TrimPrefix(strings.ToLower(filepath.Ext(*fileName)), ".")
		}
		if *format != "csv" && *format != "xlsx" {
			return errors.New(accountImportUsage)
		}
		file, e := os.Open(*fileName)
		if e != nil {
			return errors.New("could not read the import file")
		}
		raw, e := io.ReadAll(io.LimitReader(file, (10<<20)+1))
		file.Close()
		if e != nil || len(raw) == 0 || len(raw) > 10<<20 {
			return errors.New("import file must contain at most 10 MiB")
		}
		in := sessionclient.AccountImportRequest{Format: *format, Content: raw, RequestID: *requestID}
		if args[0] == "import-preview" {
			if *review != "" {
				return errors.New(accountImportUsage)
			}
			if in.RequestID == "" {
				var id [16]byte
				if _, e = rand.Read(id[:]); e != nil {
					return e
				}
				in.RequestID = hex.EncodeToString(id[:])
			}
			v, e := c.PreviewAccountImport(ctx, in)
			if e != nil {
				return e
			}
			if e = json.NewEncoder(output).Encode(v); e != nil {
				return e
			}
			if len(v.Issues) > 0 {
				return errors.New("account import validation failed")
			}
			return nil
		}
		proofFile, e := os.Open(*review)
		if e != nil {
			return errors.New("could not read the preview file")
		}
		proofRaw, e := io.ReadAll(io.LimitReader(proofFile, (1<<20)+1))
		proofFile.Close()
		if e != nil || len(proofRaw) > 1<<20 {
			return errors.New("invalid preview file")
		}
		var proof sessionclient.AccountImportPreview
		if json.Unmarshal(proofRaw, &proof) != nil || proof.Token == "" || proof.RequestID == "" || len(proof.Issues) > 0 {
			return errors.New("a successful reviewed preview file is required")
		}
		in.RequestID, in.PreviewToken = proof.RequestID, proof.Token
		v, e := c.CommitAccountImport(ctx, in)
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(v)
	default:
		return errors.New(accountImportUsage)
	}
}
