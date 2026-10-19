package hostplugins

import (
	"fmt"
	"path"
	"strings"
)

func agentArguments(id string) string {
	if id == "node_exporter" {
		return "--web.listen-address=127.0.0.1:19100 --collector.disable-defaults --collector.cpu --collector.meminfo --collector.filesystem --collector.netdev --collector.loadavg --collector.uname"
	}
	return "run -config \"$c\""
}

func agentStart(id string) string {
	return "if [ \"$running\" = 0 ]; then [ ! -L \"$d/stdout.log\" ]; nohup \"$b\" " + agentArguments(id) + " > \"$d/stdout.log\" 2>&1 < /dev/null & pid=$!; sleep 1; [ -r /proc/$pid/stat ] && [ \"$(readlink /proc/$pid/exe)\" = \"$b\" ]; stamp=$(awk '{print $22}' /proc/$pid/stat); fi; [ ! -L \"$d/pid.next\" ]; printf '%s %s\\n' \"$pid\" \"$stamp\" > \"$d/pid.next\"; mv \"$d/pid.next\" \"$d/pid\"; "
}

func agentStop() string {
	return "if [ \"$running\" = 1 ]; then kill -TERM \"$pid\"; n=0; while [ -r /proc/$pid/exe ] && [ \"$(readlink /proc/$pid/exe)\" = \"$b\" ] && [ $n -lt 30 ]; do sleep 0.1; n=$((n+1)); done; if [ -r /proc/$pid/exe ] && [ \"$(readlink /proc/$pid/exe)\" = \"$b\" ]; then exit 45; fi; fi; rm -f \"$d/pid\"; "
}

// The optional supervisor uses the account's existing cron service. It needs no
// sudo or platform credentials on the host. The launcher revalidates pinned
// binary/config hashes on every boot and recovery tick, under the same lock as
// interactive lifecycle operations.
type cronPlan struct {
	launcher string
	boot     string
	tick     string
	mark     string
}

func newCronPlan(dir, id string) cronPlan {
	p := cronPlan{launcher: path.Join(dir, "agent-launcher.sh"), mark: "# jumpserver233-agent:" + id}
	command := "/bin/sh " + quote(p.launcher) + " >/dev/null 2>&1 " + p.mark
	p.boot = "@reboot " + command
	p.tick = "* * * * * " + command
	return p
}

// A percent in a cron command is interpreted even inside shell quotes. Reject
// that uncommon home path for registration, rather than reinterpret the path.
func (p cronPlan) supported() bool { return !strings.ContainsAny(p.launcher, "%\\") }

func (p cronPlan) variables() string {
	return "mark=" + quote(p.mark) + "; boot=" + quote(p.boot) + "; tick=" + quote(p.tick) + "; "
}

func cronRead() string {
	return "command -v crontab >/dev/null 2>&1 || exit 48; if cron=$(LC_ALL=C crontab -l 2>&1); then :; else case \"$cron\" in 'no crontab for '*) cron='';; *) exit 48;; esac; fi; [ ${#cron} -le 65536 ] || exit 48; "
}

func (p cronPlan) classify() string {
	return p.variables() + `summary=$(printf '%s\n' "$cron" | awk -v mark="$mark" -v boot="$boot" -v tick="$tick" 'index($0,mark) {if($0==boot) a++; else if($0==tick) b++; else bad=1} END {if(bad || a>1 || b>1 || a!=b) print "conflict"; else if(a==1) print "enabled"; else print "disabled"}'); `
}

func (p cronPlan) probe(dir string) string {
	if !p.supported() {
		return "printf unavailable"
	}
	return "(" + cronRead() + p.classify() + "if [ \"$summary\" = enabled ] && { [ ! -f " + quote(path.Join(dir, "autostart.enabled")) + " ] || [ -L " + quote(path.Join(dir, "autostart.enabled")) + " ] || [ ! -f " + quote(p.launcher) + " ] || [ -L " + quote(p.launcher) + " ]; }; then summary=conflict; fi; printf '%s' \"$summary\") || printf unavailable"
}

func (p cronPlan) launcherScript(base, state, check, id string, prestart ...string) string {
	return p.launcherWithMarker(base, state, check, id, "autostart.enabled", prestart...)
}
func (p cronPlan) launcherWithMarker(base, state, check, id, marker string, prestart ...string) string {
	script := "#!/bin/sh\nset -eu\numask 077\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH\n"
	for _, dir := range []string{base, path.Join(base, "plugins"), path.Dir(p.launcher)} {
		script += "[ ! -L " + quote(dir) + " ]\n"
	}
	script += "d=" + quote(path.Dir(p.launcher)) + "; [ ! -L \"$d/" + marker + "\" ] && [ -f \"$d/" + marker + "\" ]; mkdir \"$d/operation.lock\" 2>/dev/null || exit 0; trap 'rmdir \"$d/operation.lock\"' EXIT; "
	script += "[ -f \"$d/" + marker + "\" ] && [ ! -L \"$d/" + marker + "\" ]; " + state + check
	for _, step := range prestart {
		script += step
	}
	script += agentStart(id) + "\n"
	return script
}

// Changing two plugins' entries shares an account-wide lock. Unknown or partial
// entries carrying our marker are conflicts; they are never silently removed.
// A second snapshot before replacing crontab also catches external edits that
// occurred while preparing the update. crontab has no compare-and-swap API.
func (p cronPlan) replace(base string, enable bool) string {
	script := directoryLock("cron_lock", path.Join(base, "cron.lock"), 50) + "trap 'rmdir \"$d/operation.lock\"; rmdir \"$cron_lock\"' EXIT; "
	script += cronRead() + p.classify() + "[ \"$summary\" != conflict ]; previous=$cron; "
	script += `filtered=$(printf '%s\n' "$cron" | awk -v boot="$boot" -v tick="$tick" '$0!=boot && $0!=tick {print}'); `
	if enable {
		script += "if [ -n \"$filtered\" ]; then updated=$(printf '%s\\n%s\\n%s' \"$filtered\" \"$boot\" \"$tick\"); else updated=$(printf '%s\\n%s' \"$boot\" \"$tick\"); fi; "
	} else {
		script += "updated=$filtered; "
	}
	script += cronRead() + "[ \"$cron\" = \"$previous\" ]; printf '%s\\n' \"$updated\" | crontab -; "
	return script
}

func operationLock(dir string) string {
	return "d=" + quote(dir) + "; " + directoryLock("operation_lock", path.Join(dir, "operation.lock"), 50) + "trap 'rmdir \"$d/operation.lock\"' EXIT; "
}

// A recovery tick briefly owns the same lock as interactive operations. Wait
// for that holder without removing its lock or weakening crontab CAS checks.
// The launcher itself remains nonblocking to avoid stacking recovery ticks.
func directoryLock(variable, location string, attempts int) string {
	return variable + "=" + quote(location) + "; lock_wait=0; while ! mkdir \"$" + variable + "\" 2>/dev/null; do [ ! -L \"$" + variable + "\" ] || exit 44; if [ -e \"$" + variable + "\" ]; then [ -d \"$" + variable + "\" ] && [ \"$(stat -c %u \"$" + variable + "\")\" = \"$(id -u)\" ] || exit 44; fi; [ \"$lock_wait\" -lt " + fmt.Sprint(attempts) + " ] || exit 44; sleep 0.1; lock_wait=$((lock_wait+1)); done; "
}
