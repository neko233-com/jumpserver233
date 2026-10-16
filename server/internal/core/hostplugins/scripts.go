package hostplugins

func processState(dir, bin, config string) string {
	s := "d=" + quote(dir) + "; b=" + quote(bin) + "; c=" + quote(config) + "; running=0; stale=0; if [ -L \"$d/pid\" ]; then exit 42; fi; if [ -f \"$d/pid\" ]; then read -r pid stamp < \"$d/pid\" || true; case ${pid:-} in ''|*[!0-9]*) stale=1;; *) if [ -r /proc/$pid/stat ] && [ \"$(awk '{print $22}' /proc/$pid/stat)\" = \"${stamp:-invalid}\" ] && [ \"$(readlink /proc/$pid/exe)\" = \"$b\" ]; then running=1; else stale=1; fi;; esac; fi; "
	s += "if [ \"$running\" = 0 ]; then found=0; for exe in /proc/[0-9]*/exe; do if [ \"$(readlink \"$exe\" 2>/dev/null || true)\" = \"$b\" ]; then found=$((found+1)); pid=${exe#/proc/}; pid=${pid%/exe}; stamp=$(awk '{print $22}' /proc/$pid/stat); fi; done; [ $found -le 1 ]; if [ $found = 1 ]; then running=1; stale=0; fi; fi; "
	return s
}

func installationCheck(d Definition, configHash string) string {
	s := "[ ! -L \"$d/" + d.Version + "\" ] && [ ! -L \"$b\" ] && [ -f \"$b\" ] && [ ! -L \"$d/manifest\" ] && [ -f \"$d/manifest\" ]; read -r version expected config_hash < \"$d/manifest\"; [ \"$version\" = " + quote(d.Version) + " ]; [ \"$(sha256sum \"$b\" | cut -d ' ' -f 1)\" = \"$expected\" ]; "
	if d.ID == "banhack233" {
		s += "[ ! -L \"$c\" ] && [ \"$(sha256sum \"$c\" | cut -d ' ' -f 1)\" = " + quote(configHash) + " ] && [ \"$config_hash\" = " + quote(configHash) + " ]; "
	}
	return s
}

func manifestVersionGuard(version string) string {
	return "[ ! -L \"$d/manifest\" ] && [ -f \"$d/manifest\" ]; read -r actual_version ignored < \"$d/manifest\"; [ \"$actual_version\" = " + quote(version) + " ]; "
}

func snapshotStateGuard(running, autostart bool) string {
	wanted := "0"
	if running {
		wanted = "1"
	}
	s := "[ \"$running\" = " + quote(wanted) + " ]; "
	if autostart {
		s += "[ -f \"$d/autostart.enabled\" ] && [ ! -L \"$d/autostart.enabled\" ]; "
	} else {
		s += "[ ! -e \"$d/autostart.enabled\" ] && [ ! -L \"$d/autostart.enabled\" ]; "
	}
	return s
}

func absentIntents(names ...string) string {
	s := ""
	for _, name := range names {
		s += "[ ! -e \"$d/" + name + "\" ] && [ ! -L \"$d/" + name + "\" ]; "
	}
	return s
}
