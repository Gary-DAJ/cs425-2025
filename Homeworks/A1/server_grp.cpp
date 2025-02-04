#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cassert>
#include <map>
#include <thread>
#include <unordered_set>
#include <unordered_map>
#include <fstream>
#include <string>
#include <mutex>

using namespace std;

// Thread-safe data structures
mutex users_mutex;
mutex clients_mutex;
mutex groups_mutex;

unordered_map<string, int> online_users;
unordered_map<int, string> clients; // Client socket -> username
unordered_map<string, string> users; // Username -> password
unordered_map<string, unordered_set<int>> groups; // Group -> client sockets

void broadcast_message(int client_socket, const string& message) {
    // client_socket < 0 for system messages
    lock_guard<mutex> lock(clients_mutex);
    string sender = clients[client_socket];
    string msg = client_socket<0 ? message + "\n" : 
    "[Broadcast (" + sender + ")]: " + message + "\n";
    
    for(const auto& [conn_fd, name] : clients) {
        if(client_socket > 0 && write(conn_fd, msg.c_str(), msg.length()) < 0) {
            dprintf(client_socket, ("Error: Message not delivered to %s!\n", name).c_str());
        }
    }
}

int do_auth(const string& username, const string& password, int fd) {
    lock_guard<mutex> users_lock(users_mutex);
    lock_guard<mutex> clients_lock(clients_mutex);
    
    if (users.find(username) != users.end()) {
        if (users[username] == password) {
            if (online_users.find(username) != online_users.end()) {
                dprintf(fd, "Already logged in!\n");
                return -1;
            }
            online_users[username] = fd;
            clients[fd] = username;
            
            // Broadcast join message to all users
            broadcast_message(-1, username + " has joined the chat.");
            return 0;
        }
    }
    return -1;
}

void user_exit(int client_socket, const string& username) {
    {
        lock_guard<mutex> groups_lock(groups_mutex);
        // Remove user from all groups
        for(auto& [name, members] : groups) {
            members.erase(client_socket);
            if(members.empty()) {
                groups.erase(name);
            }
        }
    }
    
    {
        lock_guard<mutex> users_lock(users_mutex);
        lock_guard<mutex> clients_lock(clients_mutex);
        
        // Remove user from online users and clients maps
        online_users.erase(username);
        clients.erase(client_socket);
        
        // Broadcast leave message to all users
        broadcast_message(-1, username + " has left the server");
    }
    
    close(client_socket);
}

void private_message(int client_socket, const string& user_name, const string& pvt_msg) {
    lock_guard<mutex> lock(clients_mutex);
    string sender = clients[client_socket];
    string msg = "[Private (" + sender + ")]: " + pvt_msg + "\n";
    
    {
        lock_guard<mutex> users_lock(users_mutex);
        if(online_users.find(user_name) != online_users.end()) {
            if(write(online_users[user_name], msg.c_str(), msg.length()) < 0) {
                dprintf(client_socket, "Error: Message not delivered!\n");
            }
        } else {
            dprintf(client_socket, "Error: User not online!\n");
        }
    }
}

void create_group(int client_socket, string group_name){
    lock_guard<mutex> groups_lock(groups_mutex);
    if(groups.find(group_name)!=groups.end()){
        dprintf(client_socket, "Error: Group name already exists!");
    }else{
        groups[group_name] = unordered_set<int>();
        groups[group_name].insert(client_socket); // User who created the group is added to it
        for(auto &[conn_fd, _]: clients){ // All users online are informed about the new group
            dprintf(conn_fd, ("Group "+group_name+" created by "+clients[client_socket]).c_str());
        }
    }
}

void join_group(int client_socket, string group_name){
    lock_guard<mutex> groups_lock(groups_mutex);
    if(groups.find(group_name)==groups.end()){
        dprintf(client_socket, ("Error: Group "+group_name+" does not exist!").c_str());
    }else{
        groups[group_name].insert(client_socket); // Adding the user to the group
        for(auto &conn_fd: groups[group_name]){ // All members of the group are informed about the new member
            dprintf(conn_fd, ("\t["+group_name+"]: "+clients[client_socket]+" joined the chat.").c_str());
        }
    }
}

void group_message(int client_socket, string group_name, string group_msg){
    lock_guard<mutex> groups_lock(groups_mutex);
    if(groups.find(group_name)==groups.end()){
        dprintf(client_socket, "Error: Group does not exist!");
    }else{
        string message = "\t["+group_name+": " + "("+clients[client_socket]+")]: " + group_msg;
        for(int conn_fd : groups[group_name]){
            dprintf(conn_fd, message.c_str());
        }
    }
}

void leave_group(int client_socket, string group_name){
    if(groups.find(group_name)==groups.end()){
        dprintf(client_socket, "Error: Group does not exist!");
    }else if(groups[group_name].erase(client_socket)){
        for(auto &conn_fd: group_name){ // Inform all group members that the member has left
            dprintf(conn_fd, ("\t["+group_name+"]: "+clients[client_socket]+" left the chat.").c_str());
        }
        groups[group_name].erase(client_socket);
        // private_message(-1, clients[client_socket], "You left the group - "+group_name);
    }else{
        dprintf(client_socket, "Error: You are not part of the group!");
    }
}

int process_client_message(char *buf, int sender_fd){
    string message = buf;
    int client_socket = 1;
    if(message.starts_with("/msg")){
        size_t space1 = message.find(' ');
        size_t space2 = message.find (' ', space1 + 1);
        if(space1 != string::npos && space2 != string::npos){
            string user_name = message.substr(space1 + 1, space2 - space1 - 1);
            string pvt_msg = message.substr(space2 + 1);
            if (online_users.find(user_name) == online_users.end()) {
                dprintf(sender_fd, "[server] Error: user %s is not online", user_name.c_str());
                return 10;
            }
            auto it = online_users.find(user_name);
            assert(it != online_users.end());
            int recipient_fd = it->second;
            private_message(recipient_fd, user_name, pvt_msg);
        }
    }else if(message.starts_with("/broadcast")){
        size_t space = message.find(' ');
        if(space != string::npos){
            string msg = message.substr(space + 1);
            broadcast_message(client_socket, msg);
        }
    }else if(message.starts_with("/create_group")){
        size_t space = message.find(' ');
        if(space != string::npos){
            string group_name = message.substr(space + 1);
            create_group(client_socket, group_name);
        }
    }else if(message.starts_with("/join_group")){
        size_t space = message.find(' ');
        if(space != string::npos){
            string group_name = message.substr(space + 1);
            join_group(client_socket, group_name);
        }
    }else if(message.starts_with("/group_msg")){
        size_t space1 = message.find(' ');
        size_t space2 = message.find (' ', space1 + 1);
        if(space1 != string::npos && space2 != string::npos){
            string group_name = message.substr(space1 + 1, space2 - space1 - 1);
            string group_msg = message.substr(space2 + 1);
            group_message(client_socket, group_name, group_msg);
        }
    }else if(message.starts_with("/leave_group")){
        size_t space = message.find(' ');
        if(space != string::npos){
            string group_name = message.substr(space + 1);
            leave_group(client_socket, group_name);
        }
    }
    else {
	    // invalid message
	    printf("Error: server can't understand message\n%s\n", buf);
	    return 1;
    }

    return 0;
}

// This function is called in a new thread for each connection
void process_connection(int conn_fd) {
    // Creating a new thread
	thread::id tid = this_thread::get_id();
	cout << "New thread; tid "<< tid << "\tpid: " << getpid() << "\tpgid: " << getpgid(0) << endl;
	// Reading username and password
    char username[64];
	char password[64];
	char sbuf[1024];
	int ret;

	ret = dprintf(conn_fd, "Enter username: ");
	assert(ret > 0);
	ret = read(conn_fd, username, 64);
	assert(ret < 63);
	cout << "server received bytes: " << ret << " from FD " << conn_fd << endl;
	string uname_s = username;

	char auth2[] = "Enter password: ";
	ret = dprintf(conn_fd, "Enter password: ");
	cout << "server sent bytes " << ret << " to FD " << conn_fd << endl;
	assert(ret > 0);
	ret = read(conn_fd, password, 64);
	assert(ret < 63);
	cout << "server received bytes: " << ret << " from FD " << conn_fd << endl;

	if ( do_auth(username, password, conn_fd) == -1 ) {
		dprintf(conn_fd, "Authentication failed\n");
		goto thread_exit;
	}
	ret = dprintf(conn_fd, "Authentication successful\n");
	assert (ret > 0);
	// Inserting the new user into the data structures
    clients[conn_fd] = uname_s;
	online_users[uname_s] = conn_fd;
    dprintf(conn_fd, "Welcome to the chat server!\n");

	while (1) {
		ret = read(conn_fd, sbuf, 1024);
		if (ret <= 0) {
			printf("[Server] Looks like user %s left\n", username);
			user_exit(conn_fd, username);
			goto thread_exit;
		}
		printf("Server received message from %s: (%d)\n%s\n\n", username, ret, sbuf);
		ret = process_client_message(&sbuf[0], conn_fd);
		memset(sbuf, 0, 1024);
	}

thread_exit:
	ret = close(conn_fd);
    { // Removing the user details from the data structures
        lock_guard<mutex> users_lock(users_mutex);
        lock_guard<mutex> clients_lock(clients_mutex);
        clients.erase(conn_fd);
	    online_users.erase(uname_s);
    }
	assert(ret == 0);
	cout << "*************** EXITING ************************" << endl;
	cout << "New thread; tid "<< tid << "\tpid: " << getpid() << "\tpgid: " << getpgid(0) << endl;
}

void load_users()
{
    ifstream file("users.txt");
    if (!file)
    {
        cerr << "Error: Could not open users.txt\n";
        return;
    }

    string line;
    while (getline(file, line))
    {
        size_t delimiter = line.find(':');
        if (delimiter != string::npos)
        {
            string username = line.substr(0, delimiter);
            string password = line.substr(delimiter + 1);
            users[username] = password;
        }
    }
    file.close();
}


int main () {
	int server_fd, new_socket;
	
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(server_fd > 0);

	struct sockaddr_in sock_addr;
	sock_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(12345),
		.sin_addr = {
			.s_addr = INADDR_ANY,
		}
	};
	// setsockopt() seems unnecessary for now.

	load_users();
	int ret = bind(server_fd, (struct sockaddr *) &sock_addr, sizeof(sock_addr));
	assert(ret == 0);

	ret = listen(server_fd, 5);
	assert(ret == 0);

	cout << "server listening on port " << 12345 << endl;

	unsigned sock_size = sizeof(sock_addr);
	while (1) {
		new_socket = accept(server_fd, (struct sockaddr *)&sock_addr, &sock_size);
		assert(new_socket > 0);
		std::thread t_conn(process_connection, new_socket);

		t_conn.detach();
	}

	close(new_socket);
	close(server_fd);

	return 0;
}

