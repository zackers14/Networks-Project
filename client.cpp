//============================================================================
// --- Compilation notes ---
// WIN: g++ client.cpp -lws2_32 -o client
// BSD: g++ client.cpp -lpthread -lssl -lcrypto -o client
// --- Execution notes ---
// BSD: ./client {verbose mode} {ip}
//                    0/1
//============================================================================

#define BSD

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
#include <openssl/conf.h>       // OpenSSL Configuration
#include <openssl/evp.h>        // OpenSSL symmetric encrypt/decrypt
#include <openssl/rand.h>       // For generating random nonce
#include <openssl/err.h>        // OpenSSL Error handling
#include <memory>
#include <limits>
#include <stdexcept>
#ifdef WIN
    #include <process.h>        // for threads
    #include <stddef.h>         // for threads
    #include <windows.h>        // for winsock
#endif
#ifdef BSD
    #include <sys/types.h>      // for sockets
    #include <sys/stat.h>
    #include <netinet/in.h>     // for sockets
    #include <sys/socket.h>     // for sockets
    #include <arpa/inet.h>      // for sockets
    #include <fcntl.h>          // for sockets
    #include <netdb.h>          // for sockets
    #include <pthread.h>        // for threads
    #include <unistd.h>
#endif

//----- Constants -----------------------------------------------------------
static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;

// Template lifted from OpenSSL AES Encrypt/Decrypt example
template <typename T>
struct zallocator
{
public:
    typedef T value_type;
    typedef value_type* pointer;
    typedef const value_type* const_pointer;
    typedef value_type& reference;
    typedef const value_type& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;

    pointer address (reference v) const {return &v;}
    const_pointer address (const_reference v) const {return &v;}

    pointer allocate (size_type n, const void* hint = 0) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T))
            throw std::bad_alloc();
        return static_cast<pointer> (::operator new (n * sizeof (value_type)));
    }

    void deallocate(pointer p, size_type n) {
        OPENSSL_cleanse(p, n*sizeof(T));
        ::operator delete(p);
    }

    size_type max_size() const {
        return std::numeric_limits<size_type>::max() / sizeof (T);
    }

    template<typename U>
    struct rebind
    {
        typedef zallocator<U> other;
    };

    void construct (pointer ptr, const T& val) {
        new (static_cast<T*>(ptr) ) T (val);
    }

    void destroy(pointer ptr) {
        static_cast<T*>(ptr)->~T();
    }

#if __cpluplus >= 201103L
    template<typename U, typename... Args>
    void construct (U* ptr, Args&&  ... args) {
        ::new (static_cast<void*> (ptr) ) U (std::forward<Args> (args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
#endif
};

//----- Type Definitions ----------------------------------------------------

typedef unsigned char byte;
typedef std::basic_string<char, std::char_traits<char>, zallocator<char> > secure_string;


//----- Defines -------------------------------------------------------------
#define PORT_NUM 2379		// arbitrary port number
//#define IP_ADDR  "127.0.0.1"	// TODO: make command line arg for server IP
#define DIFFIE_P 47          	// arbitrary "large" number
#define DIFFIE_G 7           	// arbitrary smaller number

using namespace std;

//----- Function prototypes -------------------------------------------------
long long int   create_shared_secret(int client_s);
long long int   power(long long int a, long long int b);
vector<int>     parse_ports(string port_pkt, int num_ports);
bool            knock_port(int port, byte[], byte[]);
void gen_params(byte key[KEY_SIZE], byte iv[BLOCK_SIZE],long long int, long long int);
void aes_encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext);
void aes_decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext);
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

//----- Using ---------------------------------------------------------------
using namespace std;
using EVP_CIPHER_CTX_free_ptr = unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

char * server_ip;
bool verbose = false;
//===== Main program ========================================================
int main(int argc, char * argv[])
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
    long long int        key, iv;               // Shared secret
#ifdef WIN
    WSAStartup(wVersionRequested, &wsaData);
#endif

    if (argc != 3){
      printf("*** ERROR - invalid number of arguments \n");
      exit(-1);
    }

    if (*argv[1] == 1){
      verbose = true;
    }

    server_ip = argv[2];

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
    server_addr.sin_addr.s_addr = inet_addr(server_ip); // IP address to use
    retcode = connect(client_s, (struct sockaddr *)&server_addr,
        sizeof(server_addr));
    if (retcode < 0)
    {
        printf("*** ERROR - connect() failed \n");
        exit(-1);
    }

    //Load Cipher
    EVP_add_cipher(EVP_aes_256_cbc());

    // Exchange shared secret
    key = create_shared_secret(client_s);
    iv = create_shared_secret(client_s);

    byte key_bytes[KEY_SIZE];
    byte iv_bytes[BLOCK_SIZE];

    gen_params(key_bytes, iv_bytes, key, iv);

    cout << "Key: " << key << endl; // TODO: print for testing purposes

    // Receive port packet
    retcode = recv(client_s, in_buf, sizeof(in_buf), 0);
    if (retcode < 0)
    {
        printf("*** ERROR - recv() failed \n");
        exit(-1);
    }
    // TODO: Unencrypt ports

    secure_string cipher_text, recovered_text;
    cipher_text = in_buf;

    aes_decrypt(key_bytes, iv_bytes, cipher_text, recovered_text);

    string reply = recovered_text.c_str();

    ports = parse_ports(reply, 3);
    // Leave main TCP socket open, sequentially knock each port with UDP
    cout << "Ports: ";
    for (int port : ports)
        cout << port << " ";
    cout << endl;

    for (int port : ports)
    {
        if(!knock_port(port, key_bytes, iv_bytes))
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

    if (verbose){
      printf("Sending x: ");
      for (int i = 0; i<strlen(c_pkt); i++){
        printf("%02X", c_pkt[i]);
      }
      printf("\n");
    }

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
bool knock_port(int port, byte key[], byte iv[])
{
#ifdef WIN
    WORD wVersionRequested = MAKEWORD(1,1);       // Stuff for WSA functions
    WSADATA wsaData;                              // Stuff for WSA functions
#endif
    int                  client_s;        // Client socket descriptor
    struct sockaddr_in   server_addr;     // Server Internet address
#ifdef WIN
    int                  addr_len;        // Internet address length
#endif
#ifdef BSD
    socklen_t            addr_len;
#endif
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
    server_addr.sin_addr.s_addr = inet_addr(server_ip); // IP address to use

    // TODO: Encrypt port number using key
    secure_string plain_text = to_string(port).c_str();
    secure_string packet, recovered_text;

    // TODO: Encrypt packet using key

    aes_encrypt(key, iv, plain_text, packet);
    //aes_decrypt(key_bytes, iv_bytes, packet, recovered_text);
    //byte key[KEY_SIZE], iv[BLOCK_SIZE];
    //gen_params(key, iv);

    //aes_encrypt(key, iv, plain_text, packet);

    // Send packet to client
    const char * c_pkt = packet.c_str();

    if (verbose){
      printf("Sending knock: ");
      for (int i = 0; i<strlen(c_pkt); i++){
        printf("%02X", c_pkt[i]);
      }
      printf("\n");
    }
    // Send knock packet to port
    retcode = sendto(client_s, c_pkt, (strlen(c_pkt) + 1), 0,
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

// Encrypts using AES, lifted from OpenSSL example
void aes_encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
    if (rc != 1)
      throw runtime_error("EVP_EncryptInit_ex failed");

    // Recovered text expands upto BLOCK_SIZE
    ctext.resize(ptext.size()+BLOCK_SIZE);
    int out_len1 = (int)ctext.size();

    rc = EVP_EncryptUpdate(ctx.get(), (byte*)&ctext[0], &out_len1, (const byte*)&ptext[0], (int)ptext.size());
    if (rc != 1)
      throw std::runtime_error("EVP_EncryptUpdate failed");

    int out_len2 = (int)ctext.size() - out_len1;
    rc = EVP_EncryptFinal_ex(ctx.get(), (byte*)&ctext[0]+out_len1, &out_len2);
    if (rc != 1)
      throw std::runtime_error("EVP_EncryptFinal_ex failed");

    // Set cipher text size now that we know it
    ctext.resize(out_len1 + out_len2);
}

// Decrypts using AES, lifted from OpenSSL example
void aes_decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
    if (rc != 1)
      throw std::runtime_error("EVP_DecryptInit_ex failed");

    // Recovered text contracts upto BLOCK_SIZE
    rtext.resize(ctext.size());
    int out_len1 = (int)rtext.size();

    rc = EVP_DecryptUpdate(ctx.get(), (byte*)&rtext[0], &out_len1, (const byte*)&ctext[0], (int)ctext.size());
    if (rc != 1)
      throw std::runtime_error("EVP_DecryptUpdate failed");

    int out_len2 = (int)rtext.size() - out_len1;
    rc = EVP_DecryptFinal_ex(ctx.get(), (byte*)&rtext[0]+out_len1, &out_len2);
    if (rc != 1)
      throw std::runtime_error("EVP_DecryptFinal_ex failed");

    // Set recovered text size now that we know it
    rtext.resize(out_len1 + out_len2);
}

// Generates Key and IV for AES, lifted from OpenSSL example
void gen_params(byte key[], byte iv[], long long int k, long long int i)
{
    string k_string = to_string(k);
    string i_string = to_string(i);

    char const *k_byte = k_string.c_str();
    char const *i_byte = i_string.c_str();

    for (int j = 0; j < KEY_SIZE; j++){
      if (j < sizeof(k_byte)){
        key[j] = k_byte[j];
      } else {
        key[j] = '0';
      }
    }
    for (int j = 0; j < BLOCK_SIZE; j++){
      if (j < sizeof(i_byte) && i_byte[j] > '0' && i_byte[j] <= '9'){
        iv[j] = i_byte[j];
      } else {
        iv[j] = '0';
      }
    }
    /*int rc = RAND_bytes(key, KEY_SIZE);
    if (rc != 1)
      throw std::runtime_error("RAND_bytes key failed");

    rc = RAND_bytes(iv, BLOCK_SIZE);
    if (rc != 1)
      throw std::runtime_error("RAND_bytes for iv failed");*/
}
