package api

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

func TestNativeClientAuxiliaryExecConcurrencyPolicyAndChannelRecycling(t *testing.T) {
	f := newNativeFixture(t)
	c := f.connect(t, "root", "root")
	// A shell and a pooled SFTP channel remain open while parallel probes finish.
	shell, e := c.NewSession()
	require.NoError(t, e)
	defer shell.Close()
	out := &nativeOutput{}
	shell.Stdout = out
	require.NoError(t, shell.Shell())
	waitNative(t, out, "搜索或编号")
	files, e := sftp.NewClient(c)
	require.NoError(t, e)
	defer files.Close()
	for round := 0; round < 3; round++ {
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s, e := c.NewSession()
				if e != nil {
					errs <- e
					return
				}
				defer s.Close()
				data, e := s.Output("uname -s")
				if e == nil && !strings.Contains(string(data), "native-exec:uname -s") {
					e = io.ErrUnexpectedEOF
				}
				errs <- e
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			require.NoError(t, e)
		}
	}
	for i := 0; i < 24; i++ {
		s, e := c.NewSession()
		require.NoError(t, e)
		require.Error(t, s.RequestSubsystem("unsupported"))
		_ = s.Close()
	}
	s, e := c.NewSession()
	require.NoError(t, e)
	data, e := s.Output("echo $HOME")
	require.NoError(t, e)
	require.Contains(t, string(data), "native-exec:echo $HOME")
	_, e = f.filters.Create(commandfilters.Input{Name: "aux-deny", Match: "exact", Pattern: "forbidden", Action: "deny", Account: "*", Priority: 100}, "root")
	require.NoError(t, e)
	s, e = c.NewSession()
	require.NoError(t, e)
	require.Error(t, s.Run("forbidden"))
	_, e = f.filters.Create(commandfilters.Input{Name: "aux-review", Match: "exact", Pattern: "reviewme", Action: "review", Account: "*", Priority: 100}, "root")
	require.NoError(t, e)
	s, e = c.NewSession()
	require.NoError(t, e)
	defer s.Close()
	done := make(chan error, 1)
	go func() { done <- s.Run("reviewme") }()
	var pending jobs.Job
	require.Eventually(t, func() bool {
		rows, _, _ := f.jobs.List("", 0, 100)
		for _, r := range rows {
			if r.Command == "reviewme" && r.State == "pending_review" {
				pending = r
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)
	_, e = f.jobs.Review(pending.ID, "root", true)
	require.NoError(t, e)
	_, e = f.jobs.Review(pending.ID, "root", true)
	require.Error(t, e)
	select {
	case e := <-done:
		require.NoError(t, e)
	case <-time.After(5 * time.Second):
		t.Fatal("approved auxiliary command did not finish")
	}
	s, e = c.NewSession()
	require.NoError(t, e)
	require.NoError(t, s.Start("aux-wait"))
	var waiting jobs.Job
	require.Eventually(t, func() bool {
		rows, _, _ := f.jobs.List("", 0, 100)
		for _, r := range rows {
			if r.Command == "aux-wait" && r.State == "running" {
				waiting = r
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, s.Close())
	require.Eventually(t, func() bool { j, e := f.jobs.Get(waiting.ID); return e == nil && j.State == "cancelled" }, 5*time.Second, 10*time.Millisecond)
	rows, total, e := f.jobs.List("", 0, 100)
	require.NoError(t, e)
	require.GreaterOrEqual(t, total, 27)
	for _, r := range rows {
		if r.State != "denied" {
			require.NotEmpty(t, r.ConnectionScope)
		}
		require.Equal(t, "exec", r.AccessOrigin.Method)
		require.NotEmpty(t, r.OperatorID)
	}
}

func TestNativeClientSFTPHomeAndExplicitTarget(t *testing.T) {
	f := newNativeFixture(t)
	c := f.connect(t, "root#"+f.asset.ID, "root")
	client, e := sftp.NewClient(c)
	require.NoError(t, e)
	defer client.Close()
	home, e := client.RealPath(".")
	require.NoError(t, e)
	require.Equal(t, "/home/operator", home)
	require.NoError(t, client.Mkdir(home+"/.xterminal"))
	file, e := client.Create(home + "/.xterminal/info.sh")
	require.NoError(t, e)
	_, e = io.WriteString(file, "#!/bin/sh\necho owned\n")
	require.NoError(t, e)
	require.NoError(t, file.Close())
	file, e = client.Open("/" + f.asset.ID + "/.xterminal/info.sh")
	require.NoError(t, e)
	data, e := io.ReadAll(file)
	require.NoError(t, e)
	require.Contains(t, string(data), "echo owned")
	require.NoError(t, file.Close())
	_, e = client.Open(home + "/../escape")
	require.Error(t, e)
	require.NoError(t, client.Remove(home+"/.xterminal/info.sh"))
	require.NoError(t, client.RemoveDirectory(home+"/.xterminal"))
	user, e := f.auth.CreateUser("aux-ungranted", "synthetic-aux-password", "operator")
	require.NoError(t, e)
	op := f.connect(t, user.Username, "synthetic-aux-password")
	s, e := op.NewSession()
	require.NoError(t, e)
	require.Error(t, s.Run("uname -s"))
}

func TestNativeClientRealXTerminalMonitorContract(t *testing.T) {
	f := newNativeFixture(t, true)
	c := f.connect(t, "root#"+f.asset.ID, "root")
	client, e := sftp.NewClient(c)
	require.NoError(t, e)
	t.Cleanup(func() { _ = client.Close() })
	home, e := client.RealPath(".")
	require.NoError(t, e)
	dir := home + "/.xterminal"
	_, e = client.Stat(dir)
	require.True(t, os.IsNotExist(e), "disposable fixture must not contain a monitor installation")
	require.NoError(t, client.Mkdir(dir))
	var files, dirs []string
	dirs = append(dirs, dir)
	cleaned := false
	t.Cleanup(func() {
		if cleaned {
			return
		}
		for i := len(files) - 1; i >= 0; i-- {
			_ = client.Remove(files[i])
		}
		for i := len(dirs) - 1; i >= 0; i-- {
			_ = client.RemoveDirectory(dirs[i])
		}
	})
	write := func(name string, data []byte) {
		file, e := client.Create(dir + "/" + name)
		require.NoError(t, e)
		_, e = file.Write(data)
		require.NoError(t, e)
		require.NoError(t, file.Close())
		files = append(files, dir+"/"+name)
	}
	if source := os.Getenv("JMS_TEST_XTERMINAL_SCRIPTS"); source != "" {
		require.NoError(t, filepath.WalkDir(source, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(source, p)
			if e != nil {
				return e
			}
			if rel == "." {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return os.ErrPermission
			}
			name := filepath.ToSlash(rel)
			if d.IsDir() {
				if e = client.Mkdir(dir + "/" + name); e == nil {
					dirs = append(dirs, dir+"/"+name)
				}
				return e
			}
			data, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			write(name, data)
			return nil
		}))
	} else {
		write("info.sh", []byte("#!/bin/sh\necho \"<cpu>$(getconf _NPROCESSORS_ONLN)</cpu><memory>$(head -n 1 /proc/meminfo)</memory>\" > \"$HOME/.xterminal/output.stats\"\n"))
	}
	s, e := c.NewSession()
	require.NoError(t, e)
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	done := make(chan error, 1)
	var result []byte
	go func() {
		var e error
		result, e = s.Output("sh ~/.xterminal/info.sh cpu memory os fs_size network_stats; cat ~/.xterminal/output.stats")
		done <- e
	}()
	select {
	case e := <-done:
		require.NoError(t, e)
	case <-ctx.Done():
		t.Fatal("monitor query timed out")
	}
	require.NotEmpty(t, result)
	require.Contains(t, string(result), "cpu")
	require.Contains(t, string(result), "memory")
	if os.Getenv("JMS_TEST_XTERMINAL_SCRIPTS") != "" {
		require.Regexp(t, `loadTotal:\s*[1-9][0-9]*`, string(result))
		require.Regexp(t, `memory:\s*\n\s*total:\s*[1-9][0-9]*`, string(result))
		require.Contains(t, string(result), "fsSize:")
		require.Contains(t, string(result), "networkStat:")
	}
	// Monitor scripts create statistics files; remove only this fresh fixture tree.
	var clean func(string)
	clean = func(p string) {
		entries, e := client.ReadDir(p)
		require.NoError(t, e)
		for _, r := range entries {
			q := p + "/" + r.Name()
			if r.IsDir() {
				clean(q)
				require.NoError(t, client.RemoveDirectory(q))
			} else {
				require.NoError(t, client.Remove(q))
			}
		}
	}
	clean(dir)
	require.NoError(t, client.RemoveDirectory(dir))
	cleaned = true
}
