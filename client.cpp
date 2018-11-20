//============================================================================
// --- Compilation notes ---
// WIN: g++ client.cpp -lws2_32 -o client
// BSD: g++ client.cpp -pthread -o client (needs verification)
//============================================================================

#define WIN

//----- Include files --------------------------------------------------------
#include <stdio.h>              // Needed for printf()
#include <string.h>             // Needed for memcpy() and strcpy
#include <string>
#include <cstdlib>             // Needed for exit()
#include <math.h>               // Used in Diffie-Hellman calculations
#include <vector>               // Convenient container
#include <iostream>             // cout, cin
#include <sstream>              // Convenient type conversions
#include <cstdint>              // 
#include <ctime>               // time() used as seed for rand()
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
#define IP_ADDR  "127.0.0.1"	// TODO: make command line arg for server IP
#define DIFFIE_P 47          	// arbitrary "large" number
#define DIFFIE_G 7           	// arbitrary smaller number

using namespace std;

//----- Function prototypes -------------------------------------------------
long long int   create_shared_secret(int client_s);
long long int   power(long long int a, long long int b);
vector<int>     parse_ports(string port_pkt, int num_ports);
bool            knock_port(int port);
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

//===== Main program ======================================================== 
int main()
{
#ifdef WIN
    WORD wVersionRequested = MAKEWORD(1,1);       // Stuff for WSA functions
    WSADATA wsaData;                              // Stuff for WSA functions
#endif
    int                  client_s;          // Client socket descriptor
    struct sockaddr_in   server_addr;       // Server Internet address
    char                 out_buf[4096];     // Output buffer for data
    char                 in_buf[4096];      // Input buffer for data
    int                  retcode;           // Return code
    vector<int>          ports;             // Ports to knock
    long long int        key;               // Shared secret
#ifdef WIN
    WSAStartup(wVersionRequested, &wsaData);
#endif

    // Create initial socket
    client_s = socket(AF_INET, SOCK_STREAM, 0);
    if (client_s < 0)
    {
        printf("*** ERROR - socket() failed \n");
        exit(-1);
    }

    // Perform initial connection to server
    server_addr.sin_family = AF_INET;                 // Address family to use
    server_addr.sin_port = htons(PORT_NUM);           // Port num to use
    server_addr.sin_addr.s_addr = inet_addr(IP_ADDR); // IP address to use
    retcode = connect(client_s, (struct sockaddr *)&server_addr,
        sizeof(server_addr));
    if (retcode < 0)
    {
        printf("*** ERROR - connect() failed \n");
        exit(-1);
    }

    // Exchange shared secret
    key = create_shared_secret(client_s);
    cout << "Key: " << key << endl; // TODO: print for testing purposes

    // Receive port packet
    retcode = recv(client_s, in_buf, sizeof(in_buf), 0);
    if (retcode < 0)
    {
        printf("*** ERROR - recv() failed \n");
        exit(-1);
    }
    // TODO: Unencrypt ports
    string reply(in_buf);
    
    
    ports = parse_ports(reply, 3);
    // Leave main TCP socket open, sequentially knock each port with UDP
    cout << "Ports: ";
    for (int port : ports) 
        cout << port << " ";
    cout << endl;
    
    for (int port : ports) 
    {
        if(!knock_port(port))
        {
            cout << "*** ERROR - failed to knock port " << port << endl;
            exit(-1);
        }
    }

    cout << "Knocked ports successfully!" << endl;

    // // Receive webserver port packet
    // retcode = recv(client_s, in_buf, sizeof(in_buf), 0);
    // if (retcode < 0)
    // {
    //     printf("*** ERROR - recv() failed \n");
    //     exit(-1);
    // }

    // // TODO: Unencrypt port
    // string reply(in_buf);
    // ports = parse_ports(reply, 1);
    // cout << "Web port: " << port << endl;
}

/* Uses Diffie-Hellman algorithm to create shared secret */
long long int create_shared_secret(int client_s)
{
    srand(time(0) + 1234); 

    char in_buf[4096];
    int retcode;
    int b = rand() % 11 + 1;    // arbitrary number
    long long int y = power(DIFFIE_G, b); // y = G^b mod P
    long long int x;
    stringstream stream;
    
    stream << y;
    string packet = stream.str();
    const char * c_pkt = packet.c_str();
    
    // Receive y
    retcode = recv(client_s, in_buf, sizeof(in_buf), 0);
    if (retcode < 0)
    {
        printf("*** ERROR - recv() failed \n");
        exit(-1);
    }
    string reply(in_buf);
    stream = stringstream(reply);
    stream >> x;

    // Send x
    retcode = send(client_s, c_pkt, (strlen(c_pkt) + 1), 0);
    if(retcode < 0)
    {
        printf("*** ERROR - send() failed \n");
        exit(-1);
    }

    return power(x, b); // key = x^b mod P
}

/* Power function to return value of a ^ b mod P */
long long int power(long long int a, long long int b) 
{  
    if (b == 1) 
        return a;
    else
        return (((unsigned long long int)pow(a, b)) % DIFFIE_P);
} 

/* Takes string of ports from server and parses it to integers */
vector<int> parse_ports(string port_pkt, int num_ports)
{
    vector<int> ports;
    for(int i = 0; i < num_ports; i++)
    {
        try 
        {
            ports.push_back(stoi(port_pkt.substr(i*5, 5)));
        }
        catch(invalid_argument e)
        {
            cout << "Port packet format incorrect. Can't parse port." << endl;
            exit(-1);
        }
    }
    return ports;
}

/* Creates UDP socket to knock "port". Returns true if successful. */
bool knock_port(int port)
{
#ifdef WIN
    WORD wVersionRequested = MAKEWORD(1,1);       // Stuff for WSA functions
    WSADATA wsaData;                              // Stuff for WSA functions
#endif
    int                  client_s;        // Client socket descriptor
    struct sockaddr_in   server_addr;     // Server Internet address
    int                  addr_len;        // Internet address length
    char                 out_buf[4096];   // Output buffer for data
    char                 in_buf[4096];    // Input buffer for data
    int                  retcode;         // Return code
    bool                 success;

#ifdef WIN
    // This stuff initializes winsock
    WSAStartup(wVersionRequested, &wsaData);
#endif

    client_s = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_s < 0)
    {
        printf("*** ERROR - socket() failed \n");
        exit(-1);
    }

    server_addr.sin_family = AF_INET;                 // Address family to use
    server_addr.sin_port = htons(port);               // Port num to use
    server_addr.sin_addr.s_addr = inet_addr(IP_ADDR); // IP address to use
    
    // TODO: Encrypt port number using key
    strcpy(out_buf, to_string(port).c_str());


    // Send knock packet to port
    retcode = sendto(client_s, out_buf, (strlen(out_buf) + 1), 0,
        (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (retcode < 0)
    {
        printf("*** ERROR - sendto() failed \n");
        exit(-1);
    }

    // Receive response
    addr_len = sizeof(server_addr);
    retcode = recvfrom(client_s, in_buf, sizeof(in_buf), 0,
        (struct sockaddr *)&server_addr, &addr_len);
    if (retcode < 0)
    {
        printf("*** ERROR - recvfrom() failed \n");
        exit(-1);
    }

    // TODO: Decrypt response
    string reply(in_buf);
    success = (stoi(reply)) ? true : false;
    cout << port << ": " << success << endl;

    // Close socket
#ifdef WIN
    retcode = closesocket(client_s);
    if (retcode < 0)
    {
        printf("*** ERROR - closesocket() failed \n");
        exit(-1);
    }
#endif
#ifdef BSD
    retcode = close(client_s);
    if (retcode < 0)
    {
        printf("*** ERROR - close() failed \n");
        exit(-1);
    }
#endif
    
    return success;
}