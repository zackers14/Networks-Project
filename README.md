# Networks-Project

## Reverse Proxy Steps
 1. Open on 1 port (2352) "Welcome Socket"
 2. Receive UDP "Hello Packet"
 3. Responds with 3 randomized ports encrypted by shared secret
 4. Receives UDP packets at those ports in sequence
    1. If out of sequence, close ports and send failure message
    2. If more than one knock on a port, close all ports and send failure message
    3. If timeout limit is hit, close all ports and send failure message
 5. Send acknowledgments to client per knock.
 6. On final knock, send encrypted dedicated port for TCP connection
 7. This connection handles HTTP GET requests, will decrypt and forward messages to weblite and forward back response to client
 8. After 10 seconds or client requests to close connection, abort all sockets and resume listening on Welcome socket
