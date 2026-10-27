package cli

import "syscall"

func syscallEACCES() error { return syscall.EACCES }
