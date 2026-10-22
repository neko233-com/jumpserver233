// nativecheck is a disposable acceptance client, not a deployed service. Inputs
// (including credentials and optional target details) arrive only on stdin.
// Output contains booleans, hashes and counts; never target addresses or output.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type options struct{ Address, User, Password, AssetID, Title, Desc, IP, ExpectFingerprint string }

var terminalCSI = regexp.MustCompile("\x1b\\[[0-?]*[ -/]*[@-~]")

func nativeCommandCompleted(s string) bool {
	s = terminalCSI.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.Contains(s, "__JMS_NATIVE_ACCEPTED__\nLinux\n")
}

type output struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.data.Write(p)
}
func (o *output) text() string { o.mu.Lock(); defer o.mu.Unlock(); return o.data.String() }
func wait(out *output, offset int, check func(string) bool) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		value := out.text()
		if len(value) >= offset && check(value[offset:]) {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("native acceptance response missing")
}
func run(in options) (map[string]any, error) {
	if in.User == "" {
		in.User = "root"
	}
	if in.Password == "" {
		return nil, errors.New("stdin credential required")
	}
	fingerprint := ""
	c, e := ssh.Dial("tcp", in.Address, &ssh.ClientConfig{User: in.User, Auth: []ssh.AuthMethod{ssh.Password(in.Password)}, Timeout: 10 * time.Second, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint = ssh.FingerprintSHA256(key)
		if in.ExpectFingerprint != "" && fingerprint != in.ExpectFingerprint {
			return errors.New("bastion host key changed")
		}
		return nil
	}})
	if e != nil {
		return nil, errors.New("native login or host-key verification failed")
	}
	defer c.Close()
	report := map[string]any{"login": true, "fingerprint": fingerprint}
	session, e := c.NewSession()
	if e != nil {
		return nil, e
	}
	defer session.Close()
	out := &output{}
	session.Stdout = out
	session.Stderr = out
	input, e := session.StdinPipe()
	if e != nil {
		return nil, e
	}
	if e = session.RequestPty("xterm-256color", 32, 120, ssh.TerminalModes{}); e != nil {
		return nil, e
	}
	if e = session.Shell(); e != nil {
		return nil, e
	}
	if e = wait(out, 0, func(s string) bool {
		return (strings.Contains(s, "搜索或编号") || strings.Contains(s, "Search or number"))
	}); e != nil {
		return nil, e
	}
	report["interactiveMenu"] = true
	if in.AssetID != "" {
		for name, query := range map[string]string{"title": in.Title, "desc": in.Desc, "ip": in.IP} {
			if query == "" {
				continue
			}
			offset := len(out.text())
			_, _ = io.WriteString(input, "/"+query+"\r")
			if e = wait(out, offset, func(s string) bool {
				return strings.Contains(s, in.Title) && (strings.Contains(s, "搜索或编号") || strings.Contains(s, "Search or number"))
			}); e != nil {
				return nil, e
			}
			report["search_"+name] = true
		}
		if in.Title == "" {
			return nil, errors.New("a unique asset title is required")
		}
		offset := len(out.text())
		_, _ = io.WriteString(input, "/"+in.Title+"\r")
		if e = wait(out, offset, func(s string) bool {
			return strings.Contains(s, in.Title) && (strings.Contains(s, "搜索或编号") || strings.Contains(s, "Search or number"))
		}); e != nil {
			return nil, e
		}
		offset = len(out.text())
		_, _ = io.WriteString(input, "1\r")
		if e = wait(out, offset, func(s string) bool { return strings.Contains(s, "$ ") || strings.Contains(s, "# ") }); e != nil {
			return nil, e
		}
		offset = len(out.text())
		_, _ = io.WriteString(input, "printf '__JMS_NATIVE_ACCEPTED__\\n'; uname -s; id -u\r")
		if e = wait(out, offset, nativeCommandCompleted); e != nil {
			return nil, e
		}
		report["realLinuxSSH"] = true
		offset = len(out.text())
		_, _ = io.WriteString(input, "exit\r")
		if e = wait(out, offset, func(s string) bool {
			return (strings.Contains(s, "搜索或编号") || strings.Contains(s, "Search or number"))
		}); e != nil {
			return nil, e
		}
		report["returnToMenu"] = true
	}
	_, _ = io.WriteString(input, "q\r")
	if e = session.Wait(); e != nil {
		return nil, errors.New("menu did not exit cleanly")
	}
	client, e := sftp.NewClient(c)
	if e != nil {
		return nil, e
	}
	defer client.Close()
	rows, e := client.ReadDir("/")
	if e != nil {
		return nil, e
	}
	report["sftp"] = true
	report["visibleAccountDirectories"] = len(rows)
	if in.AssetID != "" {
		info, e := client.Stat("/" + in.AssetID)
		if e != nil || !info.IsDir() {
			return nil, errors.New("target account is not SFTP-authorized")
		}
		folder := "/" + in.AssetID + "/.jms233-native-qa-" + fmt.Sprint(time.Now().UnixNano())
		if e = client.Mkdir(folder); e != nil {
			return nil, e
		}
		defer func() {
			_ = client.Remove(folder + "/proof.bin")
			_ = client.Remove(folder + "/renamed.bin")
			_ = client.RemoveDirectory(folder)
		}()
		data := bytes.Repeat([]byte("native-ssh-sftp-acceptance\n"), 2048)
		file, e := client.Create(folder + "/proof.bin")
		if e != nil {
			return nil, e
		}
		_, e = file.Write(data)
		closeErr := file.Close()
		if e != nil || closeErr != nil {
			return nil, errors.New("native upload failed")
		}
		if e = client.Rename(folder+"/proof.bin", folder+"/renamed.bin"); e != nil {
			return nil, e
		}
		file, e = client.Open(folder + "/renamed.bin")
		if e != nil {
			return nil, e
		}
		got, e := io.ReadAll(io.LimitReader(file, int64(len(data))+1))
		closeErr = file.Close()
		if e != nil || closeErr != nil || !bytes.Equal(data, got) {
			return nil, errors.New("native download differs")
		}
		sum := sha256.Sum256(got)
		report["uploadDownloadSHA256"] = hex.EncodeToString(sum[:])
		report["uploadDownloadBytes"] = len(got)
		report["rename"] = true
		if e = client.Remove(folder + "/renamed.bin"); e != nil {
			return nil, e
		}
		if e = client.RemoveDirectory(folder); e != nil {
			return nil, e
		}
		_, e = client.Stat(folder)
		report["remoteCleanup"] = os.IsNotExist(e)
		if !os.IsNotExist(e) {
			return nil, errors.New("native QA directory was not cleaned")
		}
	}
	_, e = c.Dial("tcp", "127.0.0.1:22")
	if e == nil {
		return nil, errors.New("raw forwarding bypass is enabled")
	}
	report["rawForwardingDenied"] = true
	report["passed"] = true
	return report, nil
}
func main() {
	var in options
	if e := json.NewDecoder(io.LimitReader(os.Stdin, 64*1024)).Decode(&in); e != nil {
		fmt.Fprintln(os.Stderr, "invalid acceptance input")
		os.Exit(1)
	}
	result, e := run(in)
	if e != nil {
		fmt.Fprintln(os.Stderr, "native SSH/SFTP acceptance failed")
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
