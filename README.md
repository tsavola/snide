# SNI Demultiplexer

**Snide** proxies TLS connections by passing file descriptors over unix
sockets.  Target backend is chosen by eavesdropping the plaintext Server Name
Indication included in the TLS handshake.  The handshake is not actually
completed; no certificates or private keys are used.  Instead, the buffered
input is sent to the backend which can use it to do the handshake for real.
Remaining I/O bypasses Snide, as the ownership of the socket file descriptor
has been passed to the backend.

Get the proxy server:
```
go install github.com/tsavola/snide/cmd/snide@latest
```

Go API for backends: https://pkg.go.dev/github.com/tsavola/snide

