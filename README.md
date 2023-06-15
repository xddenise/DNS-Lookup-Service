This is a Java program that provides DNS lookup service with caching.

To run the program (in your terminal):
- Navigate to project root
- `make run` to compile and start the program
- `make clean` to remove the jars before recompiling

After starting the program, here are the available commands:
- `lookup [hostname] [type]`: Look up the address for `hostname`. `type` is one of A, AAAA, NS, MX, CNAME.
    - A: IPv4 address
    - AAAA: IPv6 address
    - NS: name server
    - MX: mail exchanger
    - CNAME: alias name that maps to a canonical domain name
- `trace [on|off]`: Verbose tracing setting. `trace on` for turning it on. Default is off.
- `server [IP]`: Change root DNS server to `IP`address provided. Default is `199.7.83.42`.
- `dump`: Print all DNS results in cache
- `quit`: Exit the program

Examples:
(To see the progress of finding the result, turn trace on with `trace on`)
- Basic query to a name server: `loopup www.cs.ubc.ca A`
