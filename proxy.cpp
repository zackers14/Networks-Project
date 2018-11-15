#include <stdio.h>
#include <string>
#include <stdlib.h> 
#include <unordered_map>        // Data structure keeping track of IPs
#ifdef WIN  
    #include <process.h>        // for threads
    #include <stddef.h>         // for threads
    #include <windows.h>        // winsock
#endif
#ifdef BSD
    #include <unistd.h> 
    #include <netinet/in.h> 
    #include <sys/socket.h>
    #include <pthread.h>        // for threads
#endif

#define BSD

#define PORT_NUM 2352

int main()
{
#ifdef WIN
    WORD wVersionRequested = MAKEWORD(1,1);
    WSADATA wsaData;
#endif
    int                 server_s;
    struct sockaddr_in  server_addr;
    struct sockaddr_in  client_addr;
    struct in_addr      client_ip;
    int                 addr_len;
    int                 retcode;

#ifdef
    WSAStartup(wVersionRequested, &wsaData);
#endif

    // Create server socket

    // Bind to PORT_NUM

    // recvfrom loop
    // if (dos_check_passed and sender_authenticated)
    //     pass handle_connection() to new thread

}

/* DoS defense: Checks if sender is trying to flood the server */
bool dos_check_passed(string sender_ip)
{
    // if ip not in map, add ip to map, return true
    // if ip is in map and has > certain # of pings
    // return false
    // else increment ip entry, return true
}

/* Uses nonce to make sure sender has shared secret */
bool sender_authenticated()
{
    // Sends nonce R to sender, receives K(R), unencrypts and compares to R. 
    // If same, return true, else return false
}

/* Thread process handles knocking for one client, 
 * grants webserver access if successful */
// takes sender ip address to compare future messages
#ifdef WIN
void handle_connection(void *in_arg)
#endif
#ifdef BSD
void *handle_connection(void *in_arg)
#endif
{
    // create new random knock sequence
    // send encrypted knocks to client
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

/* Generates 3 random ports */
int[] generate_knock_sequence()
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