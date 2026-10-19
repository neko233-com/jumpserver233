package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/neko233-com/jumpserver233/server/internal/core/branding"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

const brandingUsage = "usage: jms branding show | audit [--offset 0 --limit 25] | save --file CONFIG.json [--logo IMAGE | --clear-logo] [--icon IMAGE | --clear-icon] [--mark IMAGE | --clear-mark] [--login-image IMAGE | --clear-login-image]"

func runBranding(args []string) error {
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeBranding(context.Background(), c, args, os.Stdin, os.Stdout)
}
func brandingImageFile(path string, icon bool) ([]byte, error) {
	return brandingImageFileLimit(path, icon, false)
}
func brandingImageFileLimit(path string, icon, login bool) ([]byte, error) {
	limit := branding.MaxImageBytes
	if login {
		limit = branding.MaxLoginImageBytes
	}
	info, e := os.Stat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > int64(limit) {
		return nil, branding.ErrImage
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil {
		return nil, e
	}
	if login {
		return branding.PrepareLoginImage(data)
	}
	return branding.PrepareImage(data, icon)
}
func executeBranding(ctx context.Context, c *sessionclient.Client, args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return errors.New(brandingUsage)
	}
	f := flag.NewFlagSet("branding", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	file, logo, icon := f.String("file", "", ""), f.String("logo", "", ""), f.String("icon", "", "")
	clearLogo, clearIcon := f.Bool("clear-logo", false, ""), f.Bool("clear-icon", false, "")
	mark, loginImage := f.String("mark", "", ""), f.String("login-image", "", "")
	clearMark, clearLoginImage := f.Bool("clear-mark", false, ""), f.Bool("clear-login-image", false, "")
	offset, limit := f.Int("offset", 0, ""), f.Int("limit", 25, "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *offset < 0 || *offset > 100000 || *limit < 1 || *limit > 100 || *clearLogo && *logo != "" || *clearIcon && *icon != "" || *clearMark && *mark != "" || *clearLoginImage && *loginImage != "" {
		return errors.New(brandingUsage)
	}
	mutationFlags := *file != "" || *logo != "" || *icon != "" || *clearLogo || *clearIcon || *mark != "" || *loginImage != "" || *clearMark || *clearLoginImage
	emit := func(v any, e error) error {
		if e != nil {
			return e
		}
		return json.NewEncoder(output).Encode(v)
	}
	switch args[0] {
	case "show":
		if mutationFlags || *offset != 0 || *limit != 25 {
			return errors.New(brandingUsage)
		}
		return emit(c.Branding(ctx))
	case "audit":
		if mutationFlags {
			return errors.New(brandingUsage)
		}
		return emit(c.BrandingAudit(ctx, *offset, *limit))
	case "save":
		if *file == "" || *offset != 0 || *limit != 25 {
			return errors.New(brandingUsage)
		}
		reader := input
		if *file != "-" {
			f, e := os.Open(*file)
			if e != nil {
				return e
			}
			defer f.Close()
			reader = f
		}
		var in sessionclient.BrandingInput
		decoder := json.NewDecoder(io.LimitReader(reader, (6<<20)+8193))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
			return errors.New("invalid branding JSON")
		}
		if *logo != "" {
			data, e := brandingImageFile(*logo, false)
			if e != nil {
				return e
			}
			in.Logo = &data
		}
		if *clearLogo {
			data := []byte{}
			in.Logo = &data
		}
		if *icon != "" {
			data, e := brandingImageFile(*icon, true)
			if e != nil {
				return e
			}
			in.Icon = &data
		}
		if *clearIcon {
			data := []byte{}
			in.Icon = &data
		}
		if *mark != "" {
			data, e := brandingImageFile(*mark, true)
			if e != nil {
				return e
			}
			in.Mark = &data
		}
		if *clearMark {
			data := []byte{}
			in.Mark = &data
		}
		if *loginImage != "" {
			data, e := brandingImageFileLimit(*loginImage, false, true)
			if e != nil {
				return e
			}
			in.LoginImage = &data
		}
		if *clearLoginImage {
			data := []byte{}
			in.LoginImage = &data
		}
		return emit(c.SaveBranding(ctx, in))
	default:
		return errors.New(brandingUsage)
	}
}
