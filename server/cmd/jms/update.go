package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/neko233-com/jumpserver233/server/internal/buildinfo"
	"github.com/neko233-com/jumpserver233/server/internal/core/updates"
	"github.com/neko233-com/jumpserver233/server/internal/releasebundle"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
)

const updateUsage = "usage: jms update check | download --version vX.Y.Z --out NEW.tar.gz [--os OS --arch ARCH] | verify --file ARCHIVE --sha256 SHA [--os OS --arch ARCH] | stage --file ARCHIVE --sha256 SHA --root RELEASE_ROOT [--os OS --arch ARCH] | stage-status --root RELEASE_ROOT --sha256 SHA [--os OS --arch ARCH] | stage-clean --root RELEASE_ROOT [--os OS --arch ARCH] | status | audit | policy --revision N --automatic=true|false --interval-hours N | check-server --revision N --request-id ID; staging never executes software or changes the active version or application data"

func printBuildVersion(out io.Writer) error {
	return json.NewEncoder(out).Encode(map[string]string{"version": buildinfo.Version, "commit": buildinfo.Commit, "built_at": buildinfo.BuiltAt, "os": runtime.GOOS, "arch": runtime.GOARCH})
}
func runUpdate(args []string) error {
	if len(args) == 0 {
		return errors.New(updateUsage)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if args[0] == "install" || args[0] == "install-status" || args[0] == "install-recover" || args[0] == "run" {
		return executeInstallation(ctx, args, os.Stdin, os.Stdout, os.Stderr, promptBackupPassphrase)
	}
	if args[0] == "stage" || args[0] == "stage-status" || args[0] == "stage-clean" {
		return executeStage(ctx, args, os.Stdout)
	}
	if args[0] == "check" || args[0] == "download" || args[0] == "verify" {
		return executeUpdate(ctx, args, os.Stdout, func(platform, arch string) *updates.Feed {
			return updates.NewFeed(buildinfo.Version, platform, arch, nil)
		})
	}
	endpoint := os.Getenv("JMS_SERVER_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	client, e := clientFromEnvironment(endpoint, "")
	if e != nil {
		return e
	}
	return executeServerUpdate(ctx, client, args, os.Stdout)
}

func executeStage(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(updateUsage)
	}
	fs := flag.NewFlagSet("update stage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", "", "")
	archive := fs.String("file", "", "")
	sha := fs.String("sha256", "", "")
	platform := fs.String("os", runtime.GOOS, "")
	arch := fs.String("arch", runtime.GOARCH, "")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *root == "" || !updates.Supported(*platform, *arch) {
		return errors.New(updateUsage)
	}
	var result any
	var err error
	switch args[0] {
	case "stage":
		if *archive == "" || *sha == "" {
			return errors.New(updateUsage)
		}
		result, err = releasebundle.Stage(ctx, *archive, *sha, *platform, *arch, *root)
	case "stage-status":
		if *archive != "" || *sha == "" {
			return errors.New(updateUsage)
		}
		result, err = releasebundle.InspectStage(ctx, *root, *sha, *platform, *arch)
	case "stage-clean":
		if *archive != "" || *sha != "" {
			return errors.New(updateUsage)
		}
		var count int
		count, err = releasebundle.CleanStages(ctx, *root, *platform, *arch)
		result = map[string]int{"cleaned_stages": count}
	default:
		return errors.New(updateUsage)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
func executeUpdate(ctx context.Context, args []string, out io.Writer, factory func(string, string) *updates.Feed) error {
	if len(args) > 0 && args[0] == "verify" {
		fs := flag.NewFlagSet("update verify", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		path := fs.String("file", "", "")
		sha := fs.String("sha256", "", "")
		platform := fs.String("os", runtime.GOOS, "")
		arch := fs.String("arch", runtime.GOARCH, "")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *path == "" || !updates.Supported(*platform, *arch) {
			return errors.New(updateUsage)
		}
		manifest, e := releasebundle.Verify(*path, *sha, *platform, *arch)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(manifest)
	}
	if len(args) == 1 && args[0] == "check" {
		result, e := factory(runtime.GOOS, runtime.GOARCH).Check(ctx, "")
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(result)
	}
	if len(args) == 0 || args[0] != "download" {
		return errors.New(updateUsage)
	}
	fs := flag.NewFlagSet("update download", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	version := fs.String("version", "", "")
	path := fs.String("out", "", "")
	platform := fs.String("os", runtime.GOOS, "")
	arch := fs.String("arch", runtime.GOARCH, "")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *path == "" || !updates.Supported(*platform, *arch) {
		return errors.New(updateUsage)
	}
	if _, ok := updates.Version(*version); !ok {
		return errors.New(updateUsage)
	}
	result, e := factory(*platform, *arch).Download(ctx, *version, *path)
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
func executeServerUpdate(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(updateUsage)
	}
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	revision := fs.Int("revision", 0, "")
	automatic := fs.Bool("automatic", false, "")
	hours := fs.Int("interval-hours", 24, "")
	id := fs.String("request-id", "", "")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return errors.New(updateUsage)
	}
	emit := func(value any, e error) error {
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(value)
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return errors.New(updateUsage)
		}
		return emit(c.UpdateStatus(ctx))
	case "audit":
		if len(args) != 1 {
			return errors.New(updateUsage)
		}
		return emit(c.UpdateAudit(ctx))
	case "policy":
		specified := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "automatic" {
				specified = true
			}
		})
		if !specified || *revision < 1 || *hours < 1 || *hours > 168 {
			return errors.New(updateUsage)
		}
		return emit(c.SaveUpdateSettings(ctx, updates.Settings{Automatic: *automatic, IntervalHours: *hours, Revision: *revision}))
	case "check-server":
		if *revision < 1 || *id == "" {
			return errors.New(updateUsage)
		}
		return emit(c.CheckUpdates(ctx, *revision, *id))
	default:
		return errors.New(updateUsage)
	}
}
