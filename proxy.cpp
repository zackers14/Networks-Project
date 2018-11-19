#define WIN

//----- Include files --------------------------------------------------------
#include <stdio.h>              // Needed for printf()
#include <string.h>             // Needed for memcpy() and strcpy
#include <string>
#include <stdlib.h>             // Needed for exit() 
#include <unordered_map>        // data structure keeping track of IPs
#include <math.h>
#include <vector>
#include <iostream>
#include <sstream>
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

//----- Defines -------------------------------------------------------------
#define PORT_NUM 2352			// arbitrary port number	
#define DIFFIE_P 1234567891 	// arbitrary large number
#define DIFFIE_G 177        	// arbitrary smaller number

using namespace std;

//----- Function prototypes -------------------------------------------------
bool            ip_verified(in_addr client_ip);
bool            create_knock_socket(int port_num);
vector<int>     generate_knock_sequence();
long long int   create_shared_secret(struct connection_info* conn);
long long int   power(long long int a, long long int b);
#ifdef WIN
void            handle_connection(void *in_arg);
#endif
#ifdef BSD
void*           handle_connection(void *in_arg);
#endif

//----- Struct definitions --------------------------------------------------
struct connection_info {    // Needed to pass multiple args to new thread
	connection_info(int server_s, int client_s, struct sockaddr_in client_address)
	{
        server_socket = server_s;
		client_socket = client_s;
		client_addr = client_addr;
	}
	int server_socket;
	int client_socket;
	struct sockaddr_in client_addr;
};

//----- Global variables ----------------------------------------------------
unordered_map<int, int> ip_addresses;
unordered_map<int, int> ports_in_use;

//===== Main program ========================================================
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
		
		connection_info thread_args = connection_info(server_s, client_s, client_addr);
        
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
#ifdef WIN
void handle_connection(void *in_args)
#endif
#ifdef BSD
void *handle_connection(void *in_args)
#endif
{
	struct connection_info *connection = reinterpret_cast<struct connection_info *>(in_args);
    int server_s = connection->server_socket;
	int client_s = connection->client_socket;
	struct sockaddr_in client_addr = connection->client_addr;
	
    // make unique shared secret
    int key = create_shared_secret(connection);
    
    // create new random knock sequence
    vector<int> ports = generate_knock_sequence();

    // create a packet for knocks
    std::stringstream stream;
    for (int i = 0; i < 3; i++)
    {
        stream << ports[i];
    }
    string packet = stream.str();
    
    // encrypt packet using key


    // send packet to client
    int retcode = sendto(server_s, packet.c_str(), sizeof(packet), 0,
        (struct sockaddr *)&client_addr, sizeof(client_addr));
    if (retcode < 0)
    {
        printf("*** ERROR - sendto() failed \n");
        exit(-1);
    }
    
    // call create_knock_socket for each port
    // *must be changed to sequential implementation
    for(int port : ports)
    {
        if (!create_knock_socket(port)) // knock failed
        {
            // send failure mesasage, close socket, terminate thread
        #ifdef WIN
            closesocket(client_s);
            _endthread();
        #endif
        #ifdef BSD    
            close(client_s);
            pthread_exit(NULL);
        #endif
        }
    }

    // if all succeed, launch weblite, send client encrypted server port
    
}

/* DoS defense: Checks if sender is trying to flood the server */
bool ip_verified(in_addr client_ip)
{
    // if ip not in map, add ip to map, return true
    // if ip is in map and has > certain # of pings
    // return false
    // else increment ip entry, return true
    return true;
}

/* Uses Diffie-Hellman algorithm to create shared secret */
long long int create_shared_secret(struct connection_info* conn)
{
    struct sockaddr_in client_addr = conn->client_addr; 
    int server_s = conn->server_socket;

    int a = rand() % 20 + 1; 
    long long int x = power(DIFFIE_G, a);
    long long int y;
    
    // Send x
    int retcode = sendto(server_s, (char*)x, sizeof(long long int), 0,
        (struct sockaddr *)&client_addr, sizeof(client_addr));
    if (retcode < 0)
    {
        printf("*** ERROR - sendto() failed \n");
        exit(-1);
    }

    // Receive y
    int addr_len = sizeof(client_addr);
    retcode = recvfrom(server_s, (char *)y, sizeof(long long int), 0,
        (struct sockaddr *)&client_addr, &addr_len);
    if (retcode < 0)
    {
        printf("*** ERROR - recvfrom() failed \n");
        exit(-1);
    }

    return power(y, a);
}

/* Generates 3 random ports */
vector<int> generate_knock_sequence()
{
    vector<int> ports;
    while(ports.size() < 3) 
    {
        int port = rand() % 65000 + 10000; // random 5 digit port
        // check that port isn't in use already
        if (ports_in_use.find(port) == ports_in_use.end()) {
            ports.push_back(port);
        }
    }
    return ports;
}

/* Creates new UDP socket listening on port_num for a knock */
bool create_knock_socket(int port_num)
{
    // recvfrom needs a timeout
    // once socket is closed, remove port from global port map (if implementing that)
    return true;
}

/* Power function to return value of a ^ b mod P */
long long int power(long long int a, long long int b) 
{  
    if (b == 1) 
        return a;
    else
        return (((long long int)pow(a, b)) % DIFFIE_P);
} 