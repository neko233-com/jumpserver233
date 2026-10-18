package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

// Install a protected DACL at creation, before any capability is written.
// chmod alone does not restrict inherited Windows directory permissions.
func privateAuthTemp(dir string) (*os.File, error) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	descriptor, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;" + user.User.Sid.String() + ")")
	if e != nil {
		return nil, e
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	for i := 0; i < 8; i++ {
		var random [16]byte
		if _, e = rand.Read(random[:]); e != nil {
			return nil, e
		}
		name := filepath.Join(dir, ".jms-auth-"+hex.EncodeToString(random[:])+".tmp")
		wide, e := windows.UTF16PtrFromString(name)
		if e != nil {
			return nil, e
		}
		handle, e := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if e == windows.ERROR_FILE_EXISTS || e == windows.ERROR_ALREADY_EXISTS {
			continue
		}
		if e != nil {
			return nil, e
		}
		return os.NewFile(uintptr(handle), name), nil
	}
	return nil, errors.New("private authentication file collision limit")
}
