package main

import "syscall"

func processUsage() (int64, int64, bool) {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		return 0, 0, false
	}
	return (usage.Utime.Sec+usage.Stime.Sec)*1_000_000 + usage.Utime.Usec + usage.Stime.Usec, usage.Maxrss * 1024, true
}
