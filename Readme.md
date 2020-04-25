# Windows Netstat (user-mode)

Often I want to run `netstat.exe` and see the process names of the programs that are using ports.
However, on Windows the `-b` flag requires administrator privileges.

This implementation of netstat shows the process names without requiring admin privileges, for both TCP and UDP. Currently, it is written for IPv4 only and does not accept any arguments:

