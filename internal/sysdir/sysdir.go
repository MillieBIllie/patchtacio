// Package sysdir finds Windows' system directory (normally C:\Windows\System32)
// from the operating system itself, not from the SystemRoot environment
// variable, which any parent process can set. Programs Patchtacio starts on
// Windows (schtasks, conhost, powershell) are run by full path from there.
package sysdir
