//============================================================================
// --- Compilation notes ---
// WIN: g++ proxy.cpp -lws2_32 -o proxy
// BSD: g++ proxy.cpp -pthread -o proxy (needs verification)
//============================================================================

#define BSD

//----- Include files --------------------------------------------------------
#include <stdio.h>              // Needed for printf()
#include <string.h>             // Needed for memcpy() and strcpy
#include <cstdlib>             // Needed for exit()
#include <errno.h>
#include <unordered_map>        // data structure keeping track of IPs
#include <set>                  // data structure keeping track of ports
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
    #include <sys/stat.h>
#endif
#ifdef BSD
    #include <sys/types.h>      // for sockets
    #include <sys/stat.h>
    #include <sys/time.h>
    #include <signal.h>
    #include <stdarg.h>
    #include <netinet/in.h>     // for sockets
    #include <sys/socket.h>     // for sockets
    #include <arpa/inet.h>      // for sockets
    #include <fcntl.h>          // for sockets
    #include <netdb.h>          // for sockets
    #include <pthread.h>        // for threads
    #include <unistd.h>
    #include <sys/wait.h>
    #include <sys/ipc.h>
    #include <sys/shm.h>
    #include <semaphore.h>
#endif

//----- Defines -------------------------------------------------------------
#define PORT_NUM 2378		// arbitrary port number
#define WEBLITE_PORT 8093
#define WEBLITE_ADDR "127.0.0.1"
#define DIFFIE_P 47          	// arbitrary "large" number
#define DIFFIE_G 7           	// arbitrary smaller number
#define SHMKEY ((key_t) 9999) //Shared memory key number

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

//----- Function prototypes -------------------------------------------------
bool            ip_verified(in_addr client_ip);
bool            create_knock_socket(sockaddr_in client, int port_num, byte[], byte[]);
std::vector<int>generate_knock_sequence();
std::vector<std::string> split(const std::string&, char);
long long int   create_shared_secret(int client_s);
long long int   power(long long int a, long long int b);
void gen_params(byte key[KEY_SIZE], byte iv[BLOCK_SIZE], long long int, long long int);
void aes_encrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ptext, secure_string& ctext);
void aes_decrypt(const byte key[KEY_SIZE], const byte iv[BLOCK_SIZE], const secure_string& ctext, secure_string& rtext);
#ifdef WIN
void            handle_connection(void *in_arg);
#endif
#ifdef BSD
void            timer_handler (int signum);
void            execute_with_timer(void);
void*           handle_connection(void *in_arg);
void sigint(int);
void sigquit(int);
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

//Initialize necessary variables for shared memory
int shmid;

typedef struct
{
  int wait_time;
} shared_mem;

bool verbose = false;
unordered_map<char *, int> ip_addresses;
set<int> ports_in_use;
shared_mem *wait_struc;
sem_t mutex;

//===== Main program ========================================================
int main(int argc, char * argv[]) // TODO: Command line args for 'verbose mode' and webserver file
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
#ifdef WIN
    int                 addr_len;
#endif
    char                out_buf[4096];
    char                in_buf[4096];
    int                 retcode;
#ifdef BSD
    socklen_t           addr_len;
    pthread_t           thread_id;      // Thread ID
    pthread_attr_t  attr[1]; //Attribute pointer array
    signal(SIGINT, sigint);
    signal(SIGQUIT, sigquit);
#endif
#ifdef WIN
    WSAStartup(wVersionRequested, &wsaData);
#endif

    if (argv[1]){
      verbose = true;
    }

    //Initialize necessary variables for shared memory
    char * shmadd;
    shmadd = (char *) 0;

    //Initialize the semaphore
    sem_init(&mutex, 0, 1);

    //Create a shared memory section
    if ((shmid = shmget(SHMKEY, sizeof(int), IPC_CREAT | 0666)) < 0){
      perror("shmget");
      exit(1);
    }

    //Connect to shared memory section
    if ((wait_struc = (shared_mem *) shmat(shmid, shmadd, 0)) == (shared_mem *)-1){
      perror("shmat");
      exit(0);
    }

    wait_struc->wait_time = 0;

    //Schedule thread independently
    pthread_attr_init(&attr[0]);
    pthread_attr_setscope(&attr[0], PTHREAD_SCOPE_SYSTEM);
    //Schedule thread independently END


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
            if (pthread_create(&thread_id, &attr[0], handle_connection, (void *)thread_args) != 0)
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
    char in_buf[4096];

	int client_s = ((struct connection_info *) in_args)->client_socket;
    struct sockaddr_in client_addr = ((struct connection_info *) in_args)->client_addr;
    struct in_addr client_ip;

    memcpy(&client_ip, &client_addr.sin_addr.s_addr, 4);

    // Load Cipher
    EVP_add_cipher(EVP_aes_256_cbc());



    // Make unique shared secret
    long long int key = create_shared_secret(client_s);
    long long int iv = create_shared_secret(client_s);

    byte key_bytes[KEY_SIZE];
    byte iv_bytes[BLOCK_SIZE];
    gen_params(key_bytes, iv_bytes, key, iv);
    cout << "Key: " << key << endl; // TODO: print for testing purposes
    // Create new random knock sequence
    vector<int> ports = generate_knock_sequence();

    // Create a packet for knocks
    std::stringstream stream;
    for (int i = 0; i < 3; i++)
    {
        stream << ports[i];
    }
    secure_string plain_text = stream.str().c_str();
    secure_string packet, recovered_text;

    // TODO: Encrypt packet using key

    aes_encrypt(key_bytes, iv_bytes, plain_text, packet);
    aes_decrypt(key_bytes, iv_bytes, packet, recovered_text);
    //byte key[KEY_SIZE], iv[BLOCK_SIZE];
    //gen_params(key, iv);

    //aes_encrypt(key, iv, plain_text, packet);

    // Send packet to client
    const char * c_pkt = packet.c_str();
    if (verbose){
      printf("Sending: ");
      for (int i = 0; i<strlen(c_pkt); i++){
        printf("%02X", c_pkt[i]);
      }
      printf("\n");
    }
    int retcode = send(client_s, c_pkt, (strlen(c_pkt) + 1), 0);
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
        if (!create_knock_socket(client_addr, port, key_bytes, iv_bytes)) // knock failed
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
pid_t proc;
int status;
char * ip = inet_ntoa(client_ip);

if (proc = fork() == 0 ){
  execute_with_timer();
} else{
  waitpid(proc, &status, 0);
  /*int weblite;
  struct sockaddr_in weblitesock;

  //intialize weblite socket parameters
  weblitesock.sin_family = AF_INET;
  weblitesock.sin_port = htons(WEBLITE_PORT);
  weblitesock.sin_addr.s_addr = inet_addr(WEBLITE_ADDR);
  while (waitpid(proc, &status, WNOHANG) == 0){
    // Begin receiving HTTP requests from client
    retcode = recv(client_s, in_buf, sizeof(in_buf), 0);
    if (retcode < 0)
    {
        printf("*** ERROR - recv() http request failed \n");
        exit(-1);
    }

    //decrypt request
    packet = in_buf;

    aes_decrypt(key_bytes, iv_bytes, packet, recovered_text);

    c_pkt = recovered_text.c_str();
    // Create weblite socket
    weblite = socket(AF_INET, SOCK_STREAM, 0);
    if (weblite < 0){
      printf("*** ERROR - Weblite socket failed \n");
      exit(-1);
    }
    //connect to weblite
    retcode = connect(weblite, (struct sockaddr *)&weblitesock,
        sizeof(weblitesock));
      if (retcode < 0)
      {
          printf("*** ERROR - connect() failed \n");
          exit(-1);
      }
      //Send HTTP request to weblite
      int retcode = send(weblite, c_pkt, (strlen(c_pkt) + 1), 0);
      if (retcode < 0)
      {
          printf("*** ERROR - sendto() failed \n");
          exit(-1);
      }
      //Receive file information from weblite
      retcode = recv(weblite, in_buf, sizeof(in_buf), 0);
      if (retcode < 0)
      {
          printf("*** ERROR - recv() failed \n");
          exit(-1);
      }

      //encrypt information
      plain_text = in_buf;
      aes_encrypt(key_bytes, iv_bytes, plain_text, packet);

      c_pkt = packet.c_str();
      //Send encrypted information
      retcode = send(client_s, c_pkt, (strlen(c_pkt) + 1), 0);
      if (retcode < 0)
      {
          printf("*** ERROR - sendto() failed \n");
          exit(-1);
      }
    }*/
}


}

/* DoS defense: Checks if client is trying to flood the server.
 * Increments entry for client ip every time they connect. */
// TODO: Should add timing mechanism which removes IPs after certain time
// to avoid blocking hosts unnecessarily
bool ip_verified(in_addr client_ip)
{
    char * ip = inet_ntoa(client_ip);
    // if ip exists, add 1, otherwise set to 1
    ip_addresses[ip] = (ip_addresses.find(ip) == ip_addresses.end())
        ? 1 : ip_addresses[ip] + 1;

    cout << "# Connect Attempts: " << ip_addresses[ip] << endl;

    return (ip_addresses[ip] < 20); // TODO: Turn into a constant?
}

/* Uses Diffie-Hellman algorithm to create shared secret */
long long int create_shared_secret(int client_s)
{
    srand(time(0));

    char in_buf[4096];
    int retcode;
    int a = rand() % 11 + 1;    // arbitrary number
    long long int x = power(DIFFIE_G, a); // x = G^a mod P
    long long int y;
    stringstream stream;

    stream << x;
    string packet = stream.str();
    //const char * c_pkt = packet.c_str();
    char out_buff[4096];
    strcpy(out_buff, packet.c_str());

    if (verbose){
      printf("Sending x: ");
      for (int i = 0; i<strlen(out_buff); i++){
        printf("%02X", out_buff[i]);
      }
      printf("\n");
    }

    // Send x
    retcode = send(client_s, out_buff, (strlen(out_buff) + 1), 0);
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

    return power(y, a); // key = y^a mod P
}

/* Generates 3 ports using sum of numbers in IP_address */
vector<int> generate_knock_sequence()
{
     vector<int> ports;

     while(ports.size() < 3)
     {
         int port = rand() % 65000 + 10000; // random 5 digit port
         // check that port isn't in use already

         if (ports_in_use.find(port) == ports_in_use.end()) {
             ports.push_back(port);
             ports_in_use.insert(port);
         }
     }
     return ports;
}

/* Creates new UDP socket listening on port_num for a knock */
bool create_knock_socket(sockaddr_in client, int port_num, byte key[], byte iv[])
{
    int retcode;
    int server_s;
    int client_s;
#ifdef WIN
    int addr_len;
#endif
#ifdef BSD
    socklen_t addr_len;
#endif
    char out_buf[4096];
    char in_buf[4096];
    bool success;
    struct in_addr client_ip_addr;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    struct sockaddr_in old_client = client;

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

    memcpy(&client_ip_addr, &client_addr.sin_addr.s_addr, 4);
    printf("IP address of knock = %s  port = %d \n",
        inet_ntoa(client_ip_addr), ntohs(client_addr.sin_port));

    // TODO: Decrypt packet
    secure_string cipher_text, recovered_text;
    cipher_text = in_buf;

    aes_decrypt(key, iv, cipher_text, recovered_text);

    string port_pkt = recovered_text.c_str();

    // If packet == port number, set success = true, else false;
    success = (stoi(port_pkt) == port_num) ? true : false;

    // TODO: Send appropriate response message (binary to test)
    if(success)
    {
        strcpy(out_buf, "1");
    }
    else
    {
        strcpy(out_buf, "0");
    }

    // Send knock packet to port
    retcode = sendto(server_s, out_buf, (strlen(out_buf) + 1), 0,
        (struct sockaddr *)&client_addr, sizeof(client_addr));
    if (retcode < 0)
    {
        printf("*** ERROR - sendto() failed \n");
        exit(-1);
    }
#ifdef WIN
    closesocket(server_s);
#endif
#ifdef BSD
    close(server_s);
#endif

    ports_in_use.erase(port_num);

    return success;
}

/* Power function to return value of a ^ b mod P */
long long int power(long long int a, long long int b)
{
    if (b == 1)
        return a;
    else
        return (((unsigned long long int)pow(a, b)) % DIFFIE_P);
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

//Simple string split ripped from http://ysonggit.github.io/coding/2014/12/16/split-a-string-using-c.html
vector<string> split(const string& s, char delim) {
    auto i = 0;
    vector<string> v;
    auto pos = s.find(delim);
    while (pos != string::npos) {
      v.push_back(s.substr(i, pos-i));
      i = ++pos;
      pos = s.find(delim, pos);

      if (pos == string::npos)
         v.push_back(s.substr(i, s.length()));
    }
}
#ifdef BSD

void execute_with_timer(){
  //signal(SIGINT, sigint);

  int timeout = 10;
  pid_t pid;
  struct itimerval timer;
  struct sigaction sa;
  printf("launching weblite \n");
  //setitimer (ITIMER_VIRTUAL, &timer, 0);

  if (pid = fork() == 0){

    try{
    execl("./weblite", "weblite");
  }
  catch (...){
    printf("Handled gracefully \n");
  }
  } else{
      sem_wait(&mutex);
      wait_struc->wait_time = 0;
      sem_post(&mutex);
      int stat, wpid = 0;
    do {
      wpid = waitpid(pid, &stat, WNOHANG);
      if (wpid == 0){
        sem_wait(&mutex);
        if (wait_struc->wait_time < 10){
        sem_post(&mutex);
        sleep(1);
        sem_wait(&mutex);
        wait_struc->wait_time++;
        sem_post(&mutex);
        printf("Slept for 1 sec\n");
      }
      else {
        printf("Killing\n");
        //kill(pid, SIGINT);
        kill(pid, SIGQUIT);
        waitpid(pid, &stat, 0);
        }
      }
    } while (wpid == 0 && wait_struc->wait_time <= timeout);

  }
}

void sigint(int sig){
  //Detach and remove shared memory
  if (shmdt(wait_struc) == -1){
    perror("shmdt");
    exit(-1);
  }
  shmctl(shmid, IPC_RMID, NULL);
  sem_destroy(&mutex);
  exit(0);
}

void sigquit(int sig){

}


#endif
