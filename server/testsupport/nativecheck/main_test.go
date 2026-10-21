package main

import "testing"

func TestNativeCommandCompletedNormalizesInteractiveOutput(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		want         bool
	}{
		{"CRLF", "\r\n__JMS_NATIVE_ACCEPTED__\r\nLinux\r\n0\r\n", true},
		{"line clearing", "\r\x1b[K__JMS_NATIVE_ACCEPTED__\r\nLinux\r\n1000\r\n", true},
		{"LF", "__JMS_NATIVE_ACCEPTED__\nLinux\n", true},
		{"echo only", "printf '__JMS_NATIVE_ACCEPTED__\\n'; uname -s; id -u\r\n", false},
		{"banner only", "Linux\r\n", false},
		{"wrong OS", "__JMS_NATIVE_ACCEPTED__\r\nDarwin\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeCommandCompleted(tc.output); got != tc.want {
				t.Fatalf("completed = %v, want %v", got, tc.want)
			}
		})
	}
}
