#define WIN


#include <stdio.h>              // Needed for printf()
#include <string.h>             // Needed for memcpy() and strcpy
#include <stdlib.h>             // Needed for exit() 
#include <unordered_map>        // data structure keeping track of IPs
#include <math.h>
#ifdef WIN  
    #include <process.h>        // for threads
    #include <stddef.h>         // for threads
    #include <windows.h>        // for winsock
#endif
#ifdef BSD
    #include <sys/types.h>      // for sockets
    #include <netinet/in.h>     // for sockets
    #include <sys/socket.h>     // for sockets
    #include <arpa/inet.h>      // for sockets
    #include <fcntl.h>          // for sockets
    #include <netdb.h>          // for sockets
    #include <pthread.h>        // for threads
#endif


#define PORT_NUM 2352			// arbitrary port number	
#define DIFFIE_P 1234567891 	// arbitrary large number
#define DIFFIE_G 177        	// arbitrary smaller number

bool ip_verified(in_addr client_ip);
long long int create_shared_secret(struct sockaddr_in client_addr);
int* generate_knock_sequence();
bool create_knock_socket(int port_num);
long long int power(long long int a, long long int b);
#ifdef WIN
void handle_connection(void *in_arg);
#endif
#ifdef BSD
void *handle_connection(void *in_arg);
#endif

struct connection_info {
	connection_info(int in_socket, struct sockaddr_in address)
	{
		socket = in_socket;
		addr = address;
	}
	int socket;
	struct sockaddr_in addr;
};


int main()
{
#ifdef WIN
    WORD wVersionRequested = MAKEWORD(1,1);
    WSADATA wsaData;
#endif
    int                 server_s;
    struct sockaddr_in  server_addr;
    int                 client_s;
    struct sockaddr_in  client_addr;
    struct in_addr      client_ip_addr;
    int                 addr_len;
    char                out_buf[4096];
    char                in_buf[4096];
    int                 retcode;
#ifdef BSD
    pthread_t           thread_id;      // Thread ID
#endif
#ifdef WIN
    WSAStartup(wVersionRequested, &wsaData);
#endif

    // Create server socket
    server_s = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_s < 0)
    {
        printf("*** ERROR - socket() failed \n");
        exit(-1);
    }

    // Bind to PORT_NUM
    server_addr.sin_family = AF_INET;                 // Address family to use
    server_addr.sin_port = htons(PORT_NUM);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    retcode = bind(server_s, (struct sockaddr *)&server_addr,
        sizeof(server_addr));
    if (retcode < 0)
    {
        printf("*** ERROR - bind() failed \n");
        exit(-1);
    }

    // recvfrom loop
    while (1) 
    {
        printf("Waiting for connection... \n");
        addr_len = sizeof(client_addr);
        retcode = recvfrom(server_s, in_buf, sizeof(in_buf), 0,
            (struct sockaddr *)&client_addr, &addr_len);
        if (retcode < 0)
        {
            printf("*** ERROR - recvfrom() failed \n");
            exit(-1);
        }

        // Copy the four-byte client IP address into an IP address structure
        memcpy(&client_ip_addr, &client_addr.sin_addr.s_addr, 4);

        // Print an informational message of IP address and port of the client
        printf("IP address of client = %s  port = %d) \n", inet_ntoa(client_ip_addr),
        ntohs(client_addr.sin_port));
		
		connection_info thread_args = connection_info(client_s, client_addr);
        
        // if (ip_verified(client_addr))
        if (1) {
        #ifdef WIN
            if (_beginthread(handle_connection, 4096, (void *) &thread_args) < 0)
        #endif
        #ifdef BSD
            if (pthread_create(&thread_id, NULL, handle_connection, (void *) &thread_args) != 0)
        #endif
            {
                printf("ERROR - Unable to create a thread to handle client\n");
                exit(1);
            }
            else 
            {
                printf("Thread spawned\n");
            }
        }
		else
		{
			printf("Client refused\n");
		}
    }
}

/* Thread process handles knocking for one client, 
 * grants webserver access if successful */
// takes sender ip address to compare future messages
#ifdef WIN
void handle_connection(void *in_args)
#endif
#ifdef BSD
void *handle_connection(void *in_args)
#endif
{
	struct connection_info *client = reinterpret_cast<struct connection_info *>(in_args);
	int client_s = client->socket;
	struct sockaddr_in client_addr = client->addr;
	
    // make unique shared secret
    int key = create_shared_secret(client_addr);
    // create new random knock sequence
    int* ports = generate_knock_sequence();
    // create a packet for knocks
    // send packet to client
    // call create_knock_socket for each port
        /* if ports are created simultaneously, we can detect if they are
         * knocked out of order. Would need to spawn a thread for each.
         * How much would they need to communicate? 
         * If created sequentially we wouldn't worry about out of sequence,
         * but an attacker could theoretically just scan ports in order.
         * But why would they need to do that if they have been verified? */
        // if any return false, exit
    // if all succeed, launch weblite, send client encrypted server port
}

/* DoS defense: Checks if sender is trying to flood the server */
bool ip_verified(in_addr client_ip)
{
    // if ip not in map, add ip to map, return true
    // if ip is in map and has > certain # of pings
    // return false
    // else increment ip entry, return true
}

/* Uses Diffie-Hellman algorithm to create shared secret */
long long int create_shared_secret(struct sockaddr_in client_addr)
{
    int a = rand() % 20 + 1;
    long long int x = power(DIFFIE_G, a);
    long long int y;
    // send x, receive y
    

    return power(y, a);
}

/* Generates 3 random ports */
int* generate_knock_sequence()
{
    // check that a generated port isn't in use already?
        // add to a global port map?
}

/* Creates new UDP socket listening on port_num for a knock */
bool create_knock_socket(int port_num)
{
    // recvfrom needs a timeout
    // once socket is closed, remove port from global port map (if implementing that)
}

// Power function to return value of a ^ b mod P 
long long int power(long long int a, long long int b) 
{  
    if (b == 1) 
        return a;
    else
        return (((long long int)pow(a, b)) % DIFFIE_P);
} 