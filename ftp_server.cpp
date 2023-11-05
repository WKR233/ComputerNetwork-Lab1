#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <cstring>
#include <string>
#include <unistd.h>

#define MAGIC_NUMBER_LENGTH 6
#define MAX_MESSAGE_LENGTH 20*1024*1024
#define DATA_GRAM_HEAD_LENGTH 12
#define unused 0

typedef uint8_t type;
typedef char byte;
typedef uint8_t status;
enum STATUS {connected, closed};
STATUS S=closed;

int clientfd=0;
int listenfd=0;
struct sockaddr_in server_addr;
char recv_buffer[MAX_MESSAGE_LENGTH];
char send_buffer[MAX_MESSAGE_LENGTH];
char IP[20];
int port;
const u_int8_t char1=u_int8_t(0xc1);
const u_int8_t char2=u_int8_t(0xa1);
const u_int8_t char3=u_int8_t(0x10);

/*
    definition of datagram
    m_protocol should be like "\xc1\xa1\x10ftp"
    m_type stands for the type of current datagram
    struct type is a e_num struct
    status should be 0 or 1
    m_length should be less than INT_MAX in limits.h
    it includes the head and data
*/
struct __attribute__ ((packed)) DATA_GRAM_HEAD
{
    public:
        byte m_protocol[MAGIC_NUMBER_LENGTH]; /* protocol magic number (6 bytes) */
        type m_type;                          /* type (1 byte) */
        status m_status;                      /* status (1 byte) */
        uint32_t m_length;                    /* length (4 bytes) in Big endian*/
        DATA_GRAM_HEAD(type Type, status Status, uint32_t Length);
};                                        /* align in one byte, so that there is no padding */

/* construct func of datagram head */
DATA_GRAM_HEAD::DATA_GRAM_HEAD(type Type, status Status, uint32_t Length): m_type(Type), m_status(Status), m_length(Length)
{
    m_protocol[0]=char1;
    m_protocol[1]=char2;
    m_protocol[2]=char3;
    m_protocol[3]='f';
    m_protocol[4]='t';
    m_protocol[5]='p';
}

/* the == in DATA_GRAM_HEAD */
bool operator ==(DATA_GRAM_HEAD head1, DATA_GRAM_HEAD head2)
{
    if(head1.m_status==head2.m_status&&head1.m_type==head2.m_type)
        return true;
    return false;
}

/* some datagram heads */
DATA_GRAM_HEAD OPEN_CONN_REQUEST(0xA1, unused, htonl(DATA_GRAM_HEAD_LENGTH)),
               OPEN_CONN_REPLY(0xA2, 1, htonl(DATA_GRAM_HEAD_LENGTH)),
               LIST_REQUEST(0xA3, unused, htonl(DATA_GRAM_HEAD_LENGTH)),
               LIST_REPLY(0xA4, unused, htonl(DATA_GRAM_HEAD_LENGTH)),
               GET_REQUEST(0xA5, unused, htonl(DATA_GRAM_HEAD_LENGTH)),
               GET_REPLY_NOT_FOUND(0xA6, 0, htonl(DATA_GRAM_HEAD_LENGTH)),
               GET_REPLY_FOUND(0xA6, 1, htonl(DATA_GRAM_HEAD_LENGTH)),
               FILE_DATA(0xFF, unused, htonl(DATA_GRAM_HEAD_LENGTH)),
               PUT_REQUEST(0xA7, unused, htonl(DATA_GRAM_HEAD_LENGTH)),
               PUT_REPLY(0xA8, unused, htonl(DATA_GRAM_HEAD_LENGTH)),
               SHA_REQUEST(0xA9, unused, htonl(DATA_GRAM_HEAD_LENGTH)),
               SHA_REPLY_NOT_FOUND(0xAA, 0, htonl(DATA_GRAM_HEAD_LENGTH)),
               SHA_REPLY_FOUND(0xAA, 1, htonl(DATA_GRAM_HEAD_LENGTH)),
               QUIT_REQUEST(0xAB, unused, htonl(DATA_GRAM_HEAD_LENGTH)),
               QUIT_REPLY(0xAC, unused, htonl(DATA_GRAM_HEAD_LENGTH));
DATA_GRAM_HEAD* send_head_ptr=(DATA_GRAM_HEAD*)send_buffer;
DATA_GRAM_HEAD* recv_head_ptr=(DATA_GRAM_HEAD*)recv_buffer;

/* send that can deal with long output */
ssize_t Send(DATA_GRAM_HEAD head, const char* payload=nullptr, int length=0)
{
    /* fill in the buffer and change the head */
    head.m_length=htonl(ntohl(head.m_length)+length);
    *send_head_ptr=head;
    char* payloadptr=(char*)(send_head_ptr+1);
    if(payload!=nullptr)
        std::strncpy(payloadptr, payload, length);

    size_t ret=0; /* 未被送走的字节数 */
    ssize_t b;
    while(ret<ntohl(head.m_length))
    {
        b=send(clientfd, send_buffer+ret, ntohl(head.m_length)-ret, 0); /* 先尝试一次送完剩下的 */
        if(b==0)
            std::cerr<<"Socket Closed"<<std::endl; /* 当连接断开 */
        if(b<0)
            std::cerr<<"Send Error!"<<std::endl; /* 这里可能发生了一些意料之外的情况 */
        ret+=b; /* 成功将b个byte塞进了缓冲区 */
    }
    return b;
}

/* recv that can deal with long input */
ssize_t Recv()
{
    ssize_t b;
    b=recv(clientfd, recv_buffer, DATA_GRAM_HEAD_LENGTH, 0);
    if(ntohl(recv_head_ptr->m_length)==DATA_GRAM_HEAD_LENGTH)
        return b;
    else
    {
        int already_received=0, expect_length=ntohl(recv_head_ptr->m_length)-DATA_GRAM_HEAD_LENGTH;
        while(already_received<expect_length)
        {
            int received=recv(clientfd, recv_buffer+DATA_GRAM_HEAD_LENGTH+already_received, expect_length-already_received, 0);
            if(received<0)
                std::cerr<<"Recv Error"<<std::endl;
            else if(received==0)
                std::cerr<<"Connection Closed"<<std::endl;
            already_received+=received;
        }
    }
    return b;
}

/* Parse the message received */
void Parse()
{
    Recv();
    if(*recv_head_ptr==OPEN_CONN_REQUEST)
        if(S==closed)
        {
            Send(OPEN_CONN_REPLY);
            S=connected;
        }
    if(*recv_head_ptr==QUIT_REQUEST)
    {
        if(S==connected)
        {
            Send(QUIT_REPLY);
            close(clientfd);
            S=closed;
        }
    }
    if(*recv_head_ptr==LIST_REQUEST)
    {
        FILE *fp;
        char buffer[2048];
        int i=0;
        fp=popen("ls", "r");
        if(fp==NULL)
            std::cerr<<"popen failed!"<<std::endl;
        int lsize=fread(buffer, 1, 2048, fp);
        pclose(fp);
        Send(LIST_REPLY, buffer, lsize+1);
    }
    if(*recv_head_ptr==GET_REQUEST)
    {
        std::string File=std::string((char*)recv_head_ptr+DATA_GRAM_HEAD_LENGTH);
        FILE *fp=fopen(File.c_str(), "rb");
        if(fp==NULL)
        {
            std::cerr<<"failed to find "<<File<<std::endl;
            Send(GET_REPLY_NOT_FOUND);
        }
        else
        {   
            Send(GET_REPLY_FOUND);
            char buffer[1024*1024+10];
            fread(buffer, sizeof(char), sizeof(buffer), fp);
            Send(FILE_DATA, buffer, sizeof(buffer));
        }
    }
    if(*recv_head_ptr==PUT_REQUEST)
    {
        Send(PUT_REPLY);
        std::string filename=std::string((char*)recv_head_ptr+DATA_GRAM_HEAD_LENGTH);
        ssize_t recvbyte=Recv();
        if(*recv_head_ptr==FILE_DATA)
        {
            FILE *fp=fopen(filename.c_str(), "wb");
            char* write_prt=(char*)recv_head_ptr+DATA_GRAM_HEAD_LENGTH;
            fwrite(write_prt, sizeof(char), strlen(write_prt), fp);
            fclose(fp);
        }
    }
    if(*recv_head_ptr==SHA_REQUEST)
    {
        std::string File=std::string((char*)recv_head_ptr+DATA_GRAM_HEAD_LENGTH);
        FILE *fp=fopen(File.c_str(), "rb");
        if(fp==NULL)
        {
            std::cerr<<"failed to find "<<File<<std::endl;
            Send(SHA_REPLY_NOT_FOUND);
        }
        else
        {   
            Send(SHA_REPLY_FOUND);
            char buffer[2048];
            std::string output=std::string("sha256sum ")+File;
            fp=popen(output.c_str(), "r");
            if(fp==NULL)
                std::cerr<<"popen failed!"<<std::endl;
            fgets(buffer, 2048, fp);
            Send(FILE_DATA, buffer, strlen(buffer)+1);
        }
    }
}

int main(int argc, char* argv[])
{

    char* IP;
    int port;
    IP = argv[1];
    port = atoi(argv[2]);

    listenfd = socket(AF_INET, SOCK_STREAM, 0); // 申请一个TCP的socket
    if(listenfd<0)
        std::cerr<<"Socket Error"<<std::endl;
    server_addr.sin_port = htons(u_int16_t(port)); // 在port端口监听 htons是host to network (short)的简称，表示进行大小端表示法转换，网络中一般使用大端法
    server_addr.sin_family = AF_INET; // 表示使用AF_INET地址族
    inet_pton(AF_INET, IP, &server_addr.sin_addr); // 监听IP地址，将字符串表示转化为二进制表示
    if(bind(listenfd, (struct sockaddr*)&server_addr, sizeof(server_addr))<0)
        std::cerr<<"Bind Error"<<std::endl;
    if(listen(listenfd, 128)<0)
        std::cerr<<"Listen Error"<<std::endl;
    clientfd=accept(listenfd, nullptr, nullptr);
    if(clientfd==-1)
        std::cerr<<"Accept Error"<<std::endl;
    
    while(1)
        Parse();

    return 0;
}