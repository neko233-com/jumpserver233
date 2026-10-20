package gateway

import (
	"github.com/neko233-com/jumpserver233/server/internal/terminalwire"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const maxCommandInputBytes = 32 * 1024

var (
	shellPromptPattern      = regexp.MustCompile(`(?m)(?:^|\r?\n)[^\r\n]{0,256}[$#%>]\s*$`)
	sensitivePromptPattern  = regexp.MustCompile(`(?i)(?:password|passphrase|token|secret|one[- ]time(?: password| code)?|verification code|otp|密码|口令|验证码)[^\r\n]{0,80}[:：]\s*$`)
	secretFlagPattern       = regexp.MustCompile(`(?i)(^|\s)(--?(?:password|passwd|passphrase|token|secret|api[-_]?key|access[-_]?key)(?:=|\s+))("[^"]*"|'[^']*'|[^\s]+)`)
	secretAssignmentPattern = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|ACCESS_KEY)[A-Z0-9_]*)=("[^"]*"|'[^']*'|[^\s;]+)`)
	uriCredentialPattern    = regexp.MustCompile(`(?i)(https?://)[^/@:\s]+:[^/@\s]+@`)
	sshpassPasswordPattern  = regexp.MustCompile(`(?i)(\bsshpass\s+-p\s+)("[^"]*"|'[^']*'|[^\s]+)`)
	databasePasswordPattern = regexp.MustCompile(`(?i:(\b(?:mysql|mysqldump|mariadb|mariadb-dump)\b[^\r\n]*?))(-p)("[^"]*"|'[^']*'|[^\s]+)`)
)

type commandSubmission struct {
	Directory      terminalwire.Proof
	PolicyKey      string
	ActorID, Actor string
	Command        string
	PolicyCommand  string
	Supported      bool
	Offset         int
	SubmittedAt    time.Time
	Outcome        string
	RuleName       string
	ReviewedBy     string
	ReviewID       string
}

// commandCapture only emits complete lines entered at a recognizable terminal
// prompt. It ignores password prompts and terminal control sequences so that
// interactive applications and edited history lines are not mislabeled.
type commandCapture struct {
	mu          sync.Mutex
	outputTail  []byte
	line        []byte
	atPrompt    bool
	sensitive   bool
	unsupported bool
	escape      []byte
	pasteMode   bool
	skipLF      bool
}

func newCommandCapture() *commandCapture { return &commandCapture{} }

func (c *commandCapture) ObserveOutput(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outputTail = append(c.outputTail, data...)
	if len(c.outputTail) > 2048 {
		c.outputTail = append(c.outputTail[:0], c.outputTail[len(c.outputTail)-2048:]...)
	}
	// Readline echoes may arrive one character at a time. An echoed %, #, >
	// or "password:" inside an in-progress line is not a fresh prompt. Keep
	// the complete input for policy evaluation until submission/cancellation.
	if len(c.line) > 0 || c.unsupported || len(c.escape) > 0 || c.pasteMode {
		return
	}
	text := strings.TrimRight(stripTerminalControls(c.outputTail), " \t\r\n")
	if sensitivePromptPattern.MatchString(text) {
		c.sensitive = true
		c.atPrompt = false
		c.clearLine()
		c.unsupported = false
		return
	}
	if shellPromptPattern.MatchString(text) {
		c.sensitive = false
		c.atPrompt = true
		c.clearLine()
		c.unsupported = false
	}
}

func (c *commandCapture) ObserveInput(data []byte, kernelShellRead ...bool) []commandSubmission {
	c.mu.Lock()
	defer c.mu.Unlock()
	var submissions []commandSubmission
	for index, current := range data {
		if c.skipLF {
			c.skipLF = false
			if current == '\n' {
				continue
			}
		}
		if len(c.escape) > 0 {
			c.escape = append(c.escape, current)
			if len(c.escape) > 32 {
				c.escape = c.escape[:0]
				c.unsupported = true
				continue
			}
			if escapeSequenceComplete(c.escape) {
				sequence := string(c.escape)
				switch sequence {
				case "\x1b[200~":
					c.pasteMode = true
					c.clearLine()
					c.unsupported = true
				case "\x1b[201~":
					c.pasteMode = false
					c.unsupported = true
				default:
					if c.atPrompt && !c.pasteMode {
						c.unsupported = true
					}
				}
				c.escape = c.escape[:0]
			}
			continue
		}
		if current == 0x1b {
			c.escape = append(c.escape[:0], current)
			continue
		}
		if c.pasteMode {
			continue
		}
		if current == '\r' || current == '\n' {
			if current == '\r' {
				c.skipLF = true
			}
			if c.sensitive {
				// A password-looking prompt printed by the original shell cannot
				// suppress policy checks. Keep the text secret and mark it unknown.
				if len(kernelShellRead) > 0 && kernelShellRead[0] {
					submissions = append(submissions, commandSubmission{Supported: false, Offset: index, SubmittedAt: time.Now().UTC()})
				}
				c.sensitive = false
			} else if c.atPrompt || c.unsupported {
				command := strings.TrimSpace(string(c.line))
				if c.unsupported {
					submissions = append(submissions, commandSubmission{Command: redactCommand(command), PolicyCommand: command, Supported: false, Offset: index, SubmittedAt: time.Now().UTC()})
				} else if command != "" {
					submissions = append(submissions, commandSubmission{Command: redactCommand(command), PolicyCommand: command, Supported: true, Offset: index, SubmittedAt: time.Now().UTC()})
				}
			}
			c.clearLine()
			c.atPrompt = false
			c.unsupported = false
			continue
		}
		if c.sensitive {
			continue
		}
		if !c.atPrompt {
			if current >= 0x20 || current == 0x09 || current == 0x00 {
				c.unsupported = true
			}
			continue
		}
		switch current {
		case 0x03: // Ctrl+C cancels the current line.
			c.clearLine()
			c.atPrompt = false
			c.unsupported = false
		case 0x15: // Ctrl+U clears the current line.
			c.line = c.line[:0]
		case 0x17: // Ctrl+W deletes the previous word.
			c.deletePreviousWord()
		case 0x08, 0x7f: // Backspace.
			c.deleteLastRune()
		case 0x00, 0x09:
			c.unsupported = true
		default:
			if current < 0x20 {
				c.unsupported = true
				continue
			}
			if len(c.line) >= maxCommandInputBytes {
				c.unsupported = true
				c.clearLine()
				continue
			}
			c.line = append(c.line, current)
		}
	}
	return submissions
}

func (c *commandCapture) Close() {
	c.mu.Lock()
	c.clearLine()
	for i := range c.outputTail {
		c.outputTail[i] = 0
	}
	for i := range c.escape {
		c.escape[i] = 0
	}
	c.line = nil
	c.outputTail = nil
	c.escape = nil
	c.atPrompt = false
	c.sensitive = false
	c.unsupported = false
	c.pasteMode = false
	c.skipLF = false
	c.mu.Unlock()
}

func (c *commandCapture) clearLine() {
	for i := range c.line {
		c.line[i] = 0
	}
	c.line = c.line[:0]
}

func (c *commandCapture) deleteLastRune() {
	if len(c.line) == 0 {
		return
	}
	index := len(c.line) - 1
	for index > 0 && !utf8.RuneStart(c.line[index]) {
		index--
	}
	for i := index; i < len(c.line); i++ {
		c.line[i] = 0
	}
	c.line = c.line[:index]
}

func (c *commandCapture) deletePreviousWord() {
	for len(c.line) > 0 && (c.line[len(c.line)-1] == ' ' || c.line[len(c.line)-1] == '\t') {
		c.deleteLastRune()
	}
	for len(c.line) > 0 && c.line[len(c.line)-1] != ' ' && c.line[len(c.line)-1] != '\t' {
		c.deleteLastRune()
	}
}

func escapeSequenceComplete(sequence []byte) bool {
	if len(sequence) < 2 {
		return false
	}
	if sequence[1] != '[' {
		return len(sequence) >= 2
	}
	if len(sequence) < 3 {
		return false
	}
	last := sequence[len(sequence)-1]
	return last >= 0x40 && last <= 0x7e
}

func stripTerminalControls(input []byte) string {
	output := make([]byte, 0, len(input))
	for i := 0; i < len(input); {
		if input[i] == 0x1b {
			if i+1 >= len(input) {
				break
			}
			switch input[i+1] {
			case '[':
				i += 2
				for i < len(input) {
					current := input[i]
					i++
					if current >= 0x40 && current <= 0x7e {
						break
					}
				}
			case ']', 'P', '^', '_':
				i += 2
				for i < len(input) {
					if input[i] == 0x07 {
						i++
						break
					}
					if input[i] == 0x1b && i+1 < len(input) && input[i+1] == '\\' {
						i += 2
						break
					}
					i++
				}
			default:
				i += 2
			}
			continue
		}
		current := input[i]
		i++
		if current >= 0x20 || current == '\r' || current == '\n' || current == '\t' {
			output = append(output, current)
		}
	}
	return string(output)
}

func redactCommand(command string) string {
	command = secretFlagPattern.ReplaceAllString(command, `${1}${2}[REDACTED]`)
	command = secretAssignmentPattern.ReplaceAllString(command, `${1}=[REDACTED]`)
	command = uriCredentialPattern.ReplaceAllString(command, `${1}[REDACTED]@`)
	command = sshpassPasswordPattern.ReplaceAllString(command, `${1}[REDACTED]`)
	return databasePasswordPattern.ReplaceAllString(command, `${1}${2}[REDACTED]`)
}
