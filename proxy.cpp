#define WIN

//----- Include files --------------------------------------------------------
#include <stdio.h>              // Needed for printf()
#include <string.h>             // Needed for memcpy() and strcpy
#include <string>
#include <stdlib.h>             // Needed for exit() 
#include <unordered_map>        // data structure keeping track of IPs
#include <math.h>               // Used in Diffie-Hellman calculations
#include <vector>               // Convenient container
#include <iostream>             // cout, cin
#include <sstream>              // Convenient type conversions
#include <cstdint>              // 
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
bool            create_knock_socket(sockaddr_in client, int key, int port_num);
vector<int>     generate_knock_sequence();
long long int   create_shared_secret(int client_s);
long long int   power(long long int a, long long int b);
#ifdef WIN
void            handle_connection(void *in_arg);
#endif
#ifdef BSD
void*           handle_connection(void *in_arg);
#endif

//----- Struct definitions --------------------------------------------------
struct connection_info {    // Needed to pass multiple args to new thread
	connection_info(int client_s, struct sockaddr_in client_address)
	{
		client_addr = client_address;
	    client_socket = client_s;
	}
	int client_socket;
	struct sockaddr_in client_addr;
};

//----- Global variables ----------------------------------------------------
unordered_map<char *, int> ip_addresses;
unordered_map<int, int> ports_in_use;

//===== Main program ========================================================
int main() // TODO: Command line args for 'verbose mode' and webserver file
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
    server_s = socket(AF_INET, SOCK_STREAM, 0);
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

    printf(">>> Listening on port %d <<<\n", PORT_NUM);
    if (listen(server_s, 100) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // Accept loop
    while (1) 
    {
        addr_len = sizeof(client_addr);
        client_s = accept(server_s, (struct sockaddr *)&client_addr, &addr_len);
        if (client_s == -1)
        {
            printf("*** ERROR - Unable to create a socket \n");
            exit(-1);
        }

        // Copy the four-byte client IP address into an IP address structure
        memcpy(&client_ip_addr, &client_addr.sin_addr.s_addr, 4);

        // Print an informational message of IP address and port of the client
        printf("IP address of client = %s  port = %d\n", inet_ntoa(client_ip_addr),
        ntohs(client_addr.sin_port));
		
		connection_info *thread_args = new connection_info(client_s, client_addr);

        if (ip_verified(client_ip_addr))
        {
        #ifdef WIN
            if (_beginthread(handle_connection, 4096, (void *)thread_args) < 0)
        #endif
        #ifdef BSD
            if (pthread_create(&thread_id, NULL, handle_connection, (void *)client_s) != 0)
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

/* Handles knocking for one client, grants webserver access if successful */
#ifdef WIN
void handle_connection(void *in_args)
#endif
#ifdef BSD
void *handle_connection(void *in_args)
#endif
{
    char out_buf[4096];

	struct connection_info *conn = 
        reinterpret_cast<struct connection_info *>(in_args);
	int client_s = conn->client_socket;
    struct sockaddr_in client_addr = conn->client_addr;
	
    // Make unique shared secret
    int key = create_shared_secret(client_s);
    cout << key << endl; // TODO: print for testing purposes
    // Create new random knock sequence
    vector<int> ports = generate_knock_sequence();

    // Create a packet for knocks
    std::stringstream stream;
    for (int i = 0; i < 3; i++)
    {
        stream << ports[i];
    }
    string packet = stream.str();
    
    // TODO: Encrypt packet using key


    // Send packet to client
    const char * c_pkt = packet.c_str();
    int retcode = send(client_s, c_pkt, strlen(c_pkt), 0);
    if (retcode < 0)
    {
        printf("*** ERROR - sendto() failed \n");
        exit(-1);
    }
    
    // TODO: change to parallel implementation after tests
    // TODO: need a timer to refresh when a knock occurs
    // TODO: need way to measure if ports knocked out of order
    // Call create_knock_socket for each port
    for(int port : ports)
    {
        if (!create_knock_socket(client_addr, key, port)) // knock failed
        {
            // send failure mesasage, close socket, terminate thread
            strcpy(out_buf, "Knock failed\n");
            send(client_s, out_buf, (strlen(out_buf) + 1), 0);
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

    // TODO: if all succeed, launch weblite, send client encrypted server port

}

/* DoS defense: Checks if client is trying to flood the server.
 * Increments entry for client ip every time they connect.
 * Should add timing mechanism which removes IPs after certain time to avoid 
 * blocking hosts unnecessarily */
bool ip_verified(in_addr client_ip)
{
    char * ip = inet_ntoa(client_ip);
    if (ip_addresses.find(ip) == ip_addresses.end())
    {
        ip_addresses[ip] = 1;
    } 
    else
    {
        ip_addresses[ip]++;
    }
    cout << "# Connect Attempts: " << ip_addresses[ip] << endl;
    return (ip_addresses[ip] < 5); // TODO: Turn into a constant
}

/* Uses Diffie-Hellman algorithm to create shared secret */
long long int create_shared_secret(int client_s)
{
    char in_buf[4096];
    int retcode;
    int a = rand() % 20 + 1;    // arbitrary number
    long long int x = power(DIFFIE_G, a);
    long long int y;
    stringstream stream;
    
    stream << x;
    string packet = stream.str();
    const char * c_pkt = packet.c_str();
    
    // Send x
    retcode = send(client_s, c_pkt, strlen(c_pkt), 0);
    if(retcode < 0)
    {
        printf("*** ERROR - send() failed \n");
        exit(-1);
    }

    // Receive y
    retcode = recv(client_s, in_buf, sizeof(in_buf), 0);
    if (retcode < 0)
    {
        printf("*** ERROR - recv() failed \n");
        exit(-1);
    }
    string reply(in_buf);
    stream = stringstream(reply);
    stream >> y;

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
            ports_in_use[port] = 1;
        }
    }
    return ports;
}

/* Creates new UDP socket listening on port_num for a knock */
bool create_knock_socket(sockaddr_in client, int key, int port_num)
{
    int retcode;
    int server_s;
    int client_s;
    int addr_len;
    char out_buf[4096];
    char in_buf[4096];
    struct in_addr client_ip_addr;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    struct sockaddr_in old_client = client;

    //=== TEST ==================================================
    memcpy(&client_ip_addr, &old_client.sin_addr.s_addr, 4);
    printf("Original client IP = %s  port = %d \n", 
        inet_ntoa(client_ip_addr), ntohs(old_client.sin_port));
    //===========================================================

    server_s = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_s < 0)
    {
        printf("*** ERROR - socket() failed \n");
        exit(-1);
    }

    server_addr.sin_family = AF_INET;                 // Address family to use
    server_addr.sin_port = htons(port_num);           // Port number to use
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // Listen on any IP address
    retcode = bind(server_s, (struct sockaddr *)&server_addr,
        sizeof(server_addr));
    if (retcode < 0)
    {
        printf("*** ERROR - bind() failed \n");
        exit(-1);
    }

    printf("Waiting for knock on port %d \n", port_num);
    addr_len = sizeof(client_addr);
    retcode = recvfrom(server_s, in_buf, sizeof(in_buf), 0,
        (struct sockaddr *)&client_addr, &addr_len);
    if (retcode < 0)
    {
        printf("*** ERROR - recvfrom() failed \n");
        exit(-1);
    }

#ifdef WIN
    closesocket(server_s);
#endif
#ifdef BSD
    close(server_s);
#endif

    // Erase port from port map;
    ports_in_use.erase(port_num);

    // Copy the four-byte client IP address into an IP address structure
    memcpy(&client_ip_addr, &client_addr.sin_addr.s_addr, 4);

    // Print an informational message of IP address and port of the client
    printf("IP address of knock = %s  port = %d \n", 
        inet_ntoa(client_ip_addr), ntohs(client_addr.sin_port));

    // TODO: if decrypted packet matches port number, return true, else false 

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