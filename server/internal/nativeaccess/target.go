package nativeaccess

import (
	"context"
	"errors"
	"sync"
)

var errChooseTarget = errors.New("select a host first, or use platform-user#account-id / 请先选服，或使用 平台用户#账号ID")
var errTargetBusy = errors.New("close file and monitoring channels before switching hosts / 切换主机前请关闭文件和监控连接")

// One SSH connection owns its target selection. Auxiliary channels hold a lease
// so an existing file handle or monitoring request can never move to another host.
type targetBinding struct {
	mu    sync.Mutex
	id    string
	users int
}

func (c *apiClient) selectTarget(ctx context.Context, id string) error {
	rows, e := c.assets(ctx)
	if e != nil {
		return e
	}
	allowed := false
	for _, row := range rows {
		allowed = allowed || row.ID == id && (row.Connect || row.SFTP)
	}
	if !allowed {
		return errChooseTarget
	}
	c.target.mu.Lock()
	defer c.target.mu.Unlock()
	if c.target.id != id && c.target.users != 0 {
		return errTargetBusy
	}
	c.target.id = id
	return nil
}

func (c *apiClient) holdTarget(ctx context.Context) (string, func(), error) {
	rows, e := c.assets(ctx)
	if e != nil {
		return "", nil, e
	}
	c.target.mu.Lock()
	defer c.target.mu.Unlock()
	if c.target.id == "" && len(rows) == 1 {
		c.target.id = rows[0].ID
	}
	id := c.target.id
	allowed := false
	for _, row := range rows {
		allowed = allowed || row.ID == id
	}
	if id == "" || !allowed {
		return "", nil, errChooseTarget
	}
	c.target.users++
	var once sync.Once
	return id, func() { once.Do(func() { c.target.mu.Lock(); c.target.users--; c.target.mu.Unlock() }) }, nil
}
