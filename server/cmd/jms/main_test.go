package main

import (
	"strings"
	"testing"
)

func TestCommandBlockedNoticeFollowsLocale(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	if notice := commandBlockedNotice("deny reboot"); !strings.Contains(notice, "命令已被规则") || !strings.Contains(notice, "deny reboot") {
		t.Fatalf("Chinese blocked notice = %q", notice)
	}
	t.Setenv("LC_ALL", "C")
	t.Setenv("LC_MESSAGES", "en_US.UTF-8")
	if notice := commandBlockedNotice("deny reboot"); !strings.Contains(notice, "Command blocked by rule") || !strings.Contains(notice, "deny reboot") {
		t.Fatalf("English blocked notice = %q", notice)
	}
}

func TestCommandReviewNoticeFollowsLocale(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	if notice := commandReviewNotice("command_review_pending", "review deploy"); !strings.Contains(notice, "等待管理员复核") || !strings.Contains(notice, "review deploy") {
		t.Fatalf("Chinese pending review notice = %q", notice)
	}
	t.Setenv("LC_ALL", "C")
	t.Setenv("LC_MESSAGES", "en_US.UTF-8")
	if notice := commandReviewNotice("command_review_timed_out", ""); !strings.Contains(notice, "timed out") || !strings.Contains(notice, "cancelled") {
		t.Fatalf("English timeout notice = %q", notice)
	}
}

func TestAccessReviewNoticeFollowsLocale(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	if notice := accessReviewNotice("pending"); !strings.Contains(notice, "等待管理员复核") || !strings.Contains(notice, "自动继续连接") {
		t.Fatalf("Chinese login review notice = %q", notice)
	}
	t.Setenv("LC_ALL", "C")
	t.Setenv("LC_MESSAGES", "en_US.UTF-8")
	if notice := accessReviewNotice("denied"); !strings.Contains(notice, "denied by an administrator") {
		t.Fatalf("English login review denial = %q", notice)
	}
}

func TestClientFromEnvironmentSelectsOneAuthenticationMethod(t *testing.T) {
	t.Setenv("JMS_TOKEN", "")
	t.Setenv("JMS_ACCESS_KEY_ID", "ak-0123456789abcdef0123456789abcdef")
	t.Setenv("JMS_ACCESS_KEY_SECRET", "local-test-secret")
	client, err := clientFromEnvironment("https://jumpserver.example")
	if err != nil || client == nil {
		t.Fatalf("AccessKey client = %v, %v", client, err)
	}

	t.Setenv("JMS_ACCESS_KEY_SECRET", "")
	if _, err := clientFromEnvironment("https://jumpserver.example"); err == nil {
		t.Fatal("incomplete AccessKey environment was accepted")
	}

	t.Setenv("JMS_ACCESS_KEY_SECRET", "local-test-secret")
	t.Setenv("JMS_TOKEN", "bearer-token")
	if _, err := clientFromEnvironment("https://jumpserver.example"); err == nil {
		t.Fatal("mixed Bearer and AccessKey authentication was accepted")
	}

	t.Setenv("JMS_ACCESS_KEY_ID", "")
	t.Setenv("JMS_ACCESS_KEY_SECRET", "")
	client, err = clientFromEnvironment("https://jumpserver.example")
	if err != nil || client == nil {
		t.Fatalf("Bearer client = %v, %v", client, err)
	}
}
