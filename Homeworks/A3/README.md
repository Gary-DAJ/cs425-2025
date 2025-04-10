# CS425 - Assignment 3
### Group Details 
- Adarsh Sharma (210046)
- Gary Derrick Anderson J (210383)
- Pranjal Singh (218070744)

## Usage Instructions
To compile the client and server, use the `Makefile`:
```
make
```
Run the server and the client in separate consoles. Both need root permissions.

```
# Console 1 - server
sudo ./server
```

```
# Console 2 - client
# wait for the server to start up
sudo ./client
```
To wait for the server to wake up, we make the client sleeps for two seconds after
starting up. This should avoid ordering errors.   
To run all programs in a single console:
```
make
sudo ./server &  sudo ./client
```

## Results
- The handshake is successful if the client sends sequence numbers 200 and 600.
- If the server's SYN-ACK has a sequence number other than 400, then the client
refuses to connect.
- If the ACK sequence number is not 201, as expected in TCP, then the client 
refuses to connect.
