# CS425 - Assignment 1
### Group Details 
- Adarsh Sharma (210046)
- Gary Derrick Anderson J (210383)
- Pranjal Singh (218070744)

## Server Policies
- One user can have only one live login at a time.
- The server makes an announcement when any user joins or leaves.
### Implemented Features
- We have implemented all features listed in the assignment description.
- To shut down the server gracefully, we added a `/killserver` command. This frees up the port.

### Possible Improvements
- Make a command to list users and groups available.
- Permit admin login to remove malicious users and shut down server when needed.



## Design Choices
### Multithreading
- By default, the network IO calls used are blocking in nature. Thus, to listen to multiple clients at once, we have two options:
    1. Use multiple file descriptors and poll over them, using the `poll()` function
    2. Make a thread for each user the server needs to listen to.
- We chose the second approach for its simplicity.
- For a two-way connection, a pair of threads may be needed because one blocks on the syscall to wait for a message.
- However, in this design, the server has a reactive role. Messages are sent only in response to an action from a client. 
- Thus, the thread designated to the source client is supposed to send messages to any other user, although it does not listen to most of them.
- One additional threads listens for new connection requests. Thus, there are `n+1` threads in the server for `n` live connection.

### Using Simple Unix I/O Calls
- In most cases, `read()` and `write()` syscalls are enough for our purpose.
- `dprintf()`, which directly prints to a file descriptor is even simpler as it allows us to use format specifiers, and overlook the buffer size calculation.

## Implementation
- We use global maps to store lists of online users, their sockets and authentication details. They are protected by mutexes.

### Key Data Structures Used
- `unordered_map<string, int> online_users` is a mapping from usernames to sockets for logged-in users. This is protected by `std::mutex online_users_mutex`.
- `unordered_map<int, string> clients` maps sockets to usernames. This is used to fetch usernames from sets of sockets connected to a group.
- `unordered_map<string, string> users` stores username-password pairs. It is initialized upon setting up the server.
- `unordered_map<string, unordered_set<int>> groups` maps group names to sets of sockets connected. It is protected by `std::mutex group_creation_mutex`.

### Handling Errors and Exceptions
- Errors and unreliable behaviour are common in distributed systems. Thus, we need a robust mechanism to handle them.
- We extensively use `assert()` statements for readability.
- Shutting down the server abruptly does not free its port, 12345. To shut down gracefully, we included a helper function, `kill_all_conns()`.

### High-level Functions Implemented
- `main()` has an infinite `while` loop that listens for new connections.
- It is responsible to create a new thread upon receiving a connection request.
- The new thread is called with the function `process_connection()` and the new 
socket's file descriptor as the only argument.
- `process_connection()` is responsible for authentication and receiving messages.
This function also has an infinite `while` loop, which listens to the client's connection.
- All user messages other than authentication are handled by `process_client_message()`.
This function sends private messages, group messages or broadcasts as required.
- `process_client_message()` calls the helpers listed below.

### Internal APIs and Helpers Implemented
Most internal functions have self-explanatory names. We will explain functions wherever 
necessary in this section.
- `do_auth(username, password)`: for password authentication
- `private_message()`
- `broadcast_message()`
- `create_group()`
- `user_exit()`
- `join_group()`
- `leave_group()`
- `group_message()`

## Testing
### Challenges in Testing
- Server behaviour depends on the order in which messages are received. This 
is very non-deterministic, and it is difficult to automate testing.

### Testing Using a Custom Client
For testing our server, we designed a custom client (`custom_client.cpp`).   
We made this file after modifying the given client code, `client_grp.cpp`.   
We hard-code the user's behaviour in it, such that we know the expected server behaviour 
and can compare it with the observed behaviour.  
Its flow is as follows:
- We log in using 10 clients' credentials using a script.
- Each login causes an announcement. After the first client sees 9 announcements, 
it makes a broadcast.
- At this point, the second client sees 9 messages (8 new users and one broadcast), 
and sends out another broadcast.
- Finally, all 10 clients have sent one message each and received 9-18 messages. If
this does not happen, the client raises an error.


## Restrictions
- Each connection needs a new thread with a default stack size of 8 MB. This limits 
the number of logins depending on RAM.
- There is no software limitation on the server's operation.

## Challenges Faced
- Initially, we were split between using multithreading and non-blocking IO calls. 
We decided to use multithreading for simplicity.
- Initially, there was no way to shut down the server cleanly. At times, port 12345 
would get blocked.

## Contributions
- All members contributed equally.

## Declaration and References
We declare that this submission does not contain code and documentation written
by anyone else, available on the internet or generated by AI tools.  
We used the following references on networking, multithreading and C++ mutexes:
- Stack Overflow
- Linux `man` pages
- Geeks For Geeks
- Lecture slides and sample programs uploaded by the instructor

## Feedback
This assignment helped us understand network internals better than the lectures 
and the textbook. We appreciate the instructor's and TA's efforts in it. 
