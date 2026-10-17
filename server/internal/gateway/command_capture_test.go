package gateway

import (
	"strings"
	"testing"
)

func TestCommandCaptureRecognizesPromptAndRedactsCommonCredentials(t *testing.T) {
	capture := newCommandCapture()
	capture.ObserveOutput([]byte("\x1b[32mops@host:~$ \x1b[0m"))
	submissions := capture.ObserveInput([]byte(`curl --password "not-for-audit" API_TOKEN=token-value https://user:pass@example.test/` + "\r"))
	if len(submissions) != 1 {
		t.Fatalf("captured %d commands, want 1", len(submissions))
	}
	command := submissions[0].Command
	for _, secret := range []string{"not-for-audit", "token-value", "user:pass@"} {
		if strings.Contains(command, secret) {
			t.Fatalf("command retained credential %q: %s", secret, command)
		}
	}
	for _, marker := range []string{"--password [REDACTED]", "API_TOKEN=[REDACTED]", "https://[REDACTED]@"} {
		if !strings.Contains(command, marker) {
			t.Fatalf("redacted command %q omitted %q", command, marker)
		}
	}
}

func TestCommandCaptureSuppressesPasswordPromptsAndHandlesBackspace(t *testing.T) {
	capture := newCommandCapture()
	capture.ObserveOutput([]byte("user@host:~$ "))
	if submissions := capture.ObserveInput([]byte("sudo -k\r")); len(submissions) != 1 || submissions[0].Command != "sudo -k" {
		t.Fatalf("first command submissions = %#v", submissions)
	}
	capture.ObserveOutput([]byte("[sudo] password for user: "))
	if submissions := capture.ObserveInput([]byte("very-secret\r")); len(submissions) != 0 {
		t.Fatalf("password prompt input was captured: %#v", submissions)
	}
	capture.ObserveOutput([]byte("user@host:~$ "))
	if submissions := capture.ObserveInput([]byte("echo hellp\x7fo\r")); len(submissions) != 1 || submissions[0].Command != "echo hello" {
		t.Fatalf("backspace command submissions = %#v", submissions)
	}
}

func TestCommandCaptureMarksUnrecognizedPromptsAndPastesUnsupported(t *testing.T) {
	capture := newCommandCapture()
	capture.ObserveOutput([]byte("application is ready"))
	if submissions := capture.ObserveInput([]byte("not-a-shell-command\r")); len(submissions) != 1 || submissions[0].Supported {
		t.Fatalf("unrecognized prompt input should be marked unsupported: %#v", submissions)
	}
	capture.ObserveOutput([]byte("user@host:~$ "))
	pasted := []byte("\x1b[200~echo pasted\r\necho second\x1b[201~\r")
	if submissions := capture.ObserveInput(pasted); len(submissions) != 1 || submissions[0].Supported {
		t.Fatalf("bracketed paste input should be marked unsupported: %#v", submissions)
	}
}

func TestRedactCommandCoversCommonPasswordFormsWithoutMaskingSSHPort(t *testing.T) {
	raw := "ssh -p 2222 host && sshpass -p 'ssh-secret' ssh host && mysql -pdb-secret -P 3306"
	command := redactCommand(raw)
	for _, secret := range []string{"ssh-secret", "db-secret"} {
		if strings.Contains(command, secret) {
			t.Fatalf("command retained credential %q: %s", secret, command)
		}
	}
	for _, expected := range []string{"ssh -p 2222 host", "sshpass -p [REDACTED]", "mysql -p[REDACTED] -P 3306"} {
		if !strings.Contains(command, expected) {
			t.Fatalf("redacted command %q omitted %q", command, expected)
		}
	}
}
func TestCommandCaptureKeepsFullInputDuringFragmentedReadlineEcho(t *testing.T) {
	for _, command := range []string{"printf 'SYNTHETIC_DENIED_%s\\n' NEVER", "echo 'x# y> password: '", "echo 'token: ' && echo policy-denied"} {
		capture := newCommandCapture()
		capture.ObserveOutput([]byte("ops@host:~$ "))
		for _, char := range []byte(command) {
			if got := capture.ObserveInput([]byte{char}); len(got) != 0 {
				t.Fatal("premature submission")
			}
			capture.ObserveOutput([]byte{char})
		}
		got := capture.ObserveInput([]byte{'\r'})
		if len(got) != 1 || !got[0].Supported || got[0].PolicyCommand != command {
			t.Fatalf("fragmented echo truncated policy input: %#v", got)
		}
	}
}
