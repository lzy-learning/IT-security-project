# IT-security-project
This project is a demonstration experiment of TCP/IP attacks in the Information Security Technology course project, mainly including SYN flooding attacks and a simple TCP server code based on EPOLL multiplexing, as well as related commands to resist SYN flooding attacks.

# run this project
```shell
# compile
g++ tcp_server.cpp -o tcp_server
g++ syn_flood.cpp -o syn_flood
g++ syn_flood_multi_thread.cpp -o syn_flood_multi_thread

# run
./tcp_server 8080   # or ./tcp_server 192.168.247.176 8080
# noticed that you should run the attack program with root authority, cause creating a raw socket need that
sudo ./syn_flood 192.168.247.176 8080   # or sudo ./syn_flood_multi_thread 192.168.247.176 8080 
```