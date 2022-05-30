# bcrproxy
Back-connect reverse proxy written in pure Python.
All traffic is obfuscated with a session key.
The proxy is implemented using one master socket, which connects to the server from the "victim" machine. The server then waits around for a client to use this proxy. When a client comes, it asks the "victim" for a tunnel - a new connection. When the tunnel is ready, all the traffic goes between the client and the "victim" with the server acting as an arbiter. The "victim" implements socks5 protocol, so the client sees the connection as a pure socks5 proxy. The server supports multiple "victims" and multiple clients at once with socks5 username being a unique client ID and the password set with command line arguments.
