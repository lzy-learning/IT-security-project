#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <errno.h> // errno及各种宏定义

#define SERVER_PORT 8080
#define MAX_EVENTS 1024
int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage:\n");
        printf("    ./a.out 8080\n");
        printf("    ./a.out 192.168.247.176 8080\n");
        exit(1);
    }

    unsigned short server_port;
    char server_ip[INET_ADDRSTRLEN + 1];
    if (argc < 3)
    {
        server_port = strtol(argv[1], NULL, 10);
        strncpy(server_ip, "0.0.0.0", 8);
    }
    else
    {
        strncpy(server_ip, argv[1], INET_ADDRSTRLEN);
        server_port = strtol(argv[2], NULL, 10);
    }

    sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(server_port);
    if (argc < 3)
        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        saddr.sin_addr.s_addr = inet_addr(server_ip);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket()");
        exit(-1);
    }

    int err = bind(sockfd, (const sockaddr *)&saddr, sizeof(saddr));
    if (err < 0)
    {
        perror("bind()");
        close(sockfd);
        exit(-1);
    }

    int connfd;
    sockaddr_in caddr;
    socklen_t len_caddr = sizeof(caddr);
    char cip[INET_ADDRSTRLEN] = {0};
    int cport = -1;

    char buf[512];
    char *exit_flag = (char *)"exit";
    int num_conn = 0;

    // 生成epoll文件描述符，并绑定标准输入和监听描述符
    int epollfd = epoll_create(1);
    epoll_event events[MAX_EVENTS];
    // 监听可读事件
    epoll_event ev;
    ev.data.fd = sockfd;
    ev.events = EPOLLIN;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev);

    err = listen(sockfd, 16);
    if (err < 0)
    {
        perror("listen()");
        close(sockfd);
        exit(-1);
    }

    printf("Epoll Server listen on %s:%d\n", server_ip, server_port);

    while (true)
    {
        int nready = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nready <= -1)
        {
            perror("epoll_wait()");
            break;
        }
        else if (nready == 0)
        {
            printf("timeout~\n");
            continue;
        }

        for (int i = 0; i < nready; i++)
        {
            // 有新的客户端连接
            if (events[i].data.fd == sockfd)
            {
                bzero(&caddr, sizeof(caddr));
                memset(cip, 0, INET_ADDRSTRLEN);

                connfd = accept(sockfd, (sockaddr *)&caddr, &len_caddr);
                if (connfd < 0)
                {
                    printf("events[%d]: accept()\n", i);
                    continue;
                }

                inet_ntop(AF_INET, &caddr.sin_addr.s_addr, cip, INET_ADDRSTRLEN);
                cport = ntohs(caddr.sin_port);

                printf("client [%s:%d] has connected.\n", cip, cport);

                // 增加需要监听的文件描述符
                ev.data.fd = connfd;
                ev.events = EPOLLIN;
                epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &ev);

                num_conn++;
            }
            // 有客户端进行通信或者断开
            else
            {
                int clientfd = events[i].data.fd;
                int len = recv(clientfd, buf, sizeof(buf), 0);
                // int len = recvfrom()
                if (len < 0)
                { // 现在是不可能-1的，但是如果一直while读，读空了就会返回-1
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        continue; // 资源暂不可用， 在尝试一次
                    }
                    else
                    {
                        // 出错
                        close(clientfd);
                        ev.events = EPOLLIN;
                        ev.data.fd = clientfd;
                        epoll_ctl(sockfd, EPOLL_CTL_DEL, clientfd, &ev);
                    }
                }
                else if (len == 0)
                {
                    // 注意printf函数每次要打印完整一行，不然没法打印
                    printf("client disconnected(connfd: %d).\n", clientfd);
                    // 或者在后面刷新缓冲区
                    // fflush(stdout);
                    close(clientfd);
                    ev.events = EPOLLIN;
                    ev.data.fd = clientfd;
                    epoll_ctl(sockfd, EPOLL_CTL_DEL, clientfd, &ev);
                }
                else
                {
                    printf("receive data: %s(%d)\n", buf, (int)strlen(buf));
                    len = send(events[i].data.fd, buf, strlen(buf), 0);
                    if (len < 0)
                    {
                        printf("send fail\n");
                    }
                }
            }
        }
    }
    close(sockfd);
    return 0;
}