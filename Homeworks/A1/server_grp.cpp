#include <iostream>
#include <cstring>
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cassert>
#include <map>
#include <thread>
#include <unordered_set>
#include <unordered_map>
#include <bits/stdc++.h>

using namespace std;

unordered_map<string, int> online_users;
unordered_map<int, string> clients; // Client socket -> username
unordered_map<string, string> users; // Username -> password
unordered_map<string, unordered_set<int>> groups; // Group -> client sockets

// General APIs needed:
int do_auth(string username, string password);
void private_message(int client_socket, string user_name, string pvt_msg);
void broadcast_message(int client_socket, string broadcast_msg);
void create_group(int client_socket, string group_name){
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
void user_exit(int client_socket, char* username);
void join_group(int client_socket, string group_name){
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
        if(groups[group_name].empty()){ // If no member is left in the group, delete it
            groups.erase(group_name);
        }
        // private_message(-1, clients[client_socket], "You left the group - "+group_name);
    }else{
        dprintf(client_socket, "Error: You are not part of the group!");
    }
}

int do_auth(string username, string password, int fd)
{
    if (users.find(username) != users.end()) {
        if (users[username] == password) {
            if (online_users.find(username) != online_users.end()) {
                dprintf(fd, "[server] Already logged in!\n");
                return -1;
            }
            online_users[username] = fd;
            return 0;
        }
    }
    return -1;
}

void private_message(int client_socket, string user_name, string pvt_msg){
    string msg = "[Private: ("+clients[client_socket]+")]: "+pvt_msg;
    if(online_users.find(user_name)!=online_users.end()){
        if(dprintf(online_users[user_name], msg.c_str())<0){
            dprintf(client_socket, "Error: Message not delivered!");
        }
    } else {
            dprintf(client_socket, "Error: User not online!");
    }

}
void broadcast_message(int client_socket, string broadcast_msg){
    string msg = "[Broadcast: (]"+clients[client_socket]+")]: "+broadcast_msg;
    for(auto &[conn_fd, name]: clients){
        if(dprintf(conn_fd, msg.c_str())<0){
            dprintf(client_socket, ("Error: Message not delivered to " + name + "!").c_str());
        }
    }
}

void user_exit(int socket, char *username) {
    for(auto &[name, conn_fds]: groups){ // Remove the user from all groups
        leave_group(socket, name);
    }
    // Remove the user from all maps
    online_users.erase(username);
    clients.erase(socket);
    int ret = close(socket); // Close the connection
    assert(ret == 0);
};

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
void process_connection(
		int conn_fd
		) {
	std::thread::id tid = this_thread::get_id();
	cout << "New thread; tid "<< tid << "\tpid: " << getpid() << "\tpgid: " << getpgid(0) << endl;
	char username[64];
	char password[64];
	char auth1[] = "Enter username: ";
	char sbuf[1024];
	int ret;

	ret = write(conn_fd, auth1, strlen(auth1) + 1);
	cout << "server sent bytes " << ret << " to FD " << conn_fd << endl;
	assert(ret == 17);
	ret = read(conn_fd, username, 64);
	assert(ret < 63);
	cout << "server received bytes: " << ret << " from FD " << conn_fd << endl;
	string uname_s = username;

	char auth2[] = "Enter password: ";
	ret = write(conn_fd, auth2, strlen(auth1) + 1);
	cout << "server sent bytes " << ret << " to FD " << conn_fd << endl;
	assert(ret == 17);
	ret = read(conn_fd, password, 64);
	assert(ret < 63);
	cout << "server received bytes: " << ret << " from FD " << conn_fd << endl;

	ret = do_auth(username, password, conn_fd);
	if (ret == -1) {
		dprintf(conn_fd, "Authentication failed");
		goto thread_exit;
	}
	ret = dprintf(conn_fd, "Authentication successful");
	assert (ret > 10);
	clients[conn_fd] = uname_s;
	online_users[uname_s] = conn_fd;
    dprintf(conn_fd, "Welcome to the chat server!");

	while (1) {
		ret = read(conn_fd, sbuf, 1024);
		if (ret <= 0) {
			printf("[server] looks like user %s left\n", username);
			user_exit(conn_fd, username);
			goto thread_exit;
		}
		printf("server received message from %s: (%d)\n%s\n\n", username, ret, sbuf);
		ret = process_client_message(&sbuf[0], conn_fd);
		if (ret == 1)
			goto thread_exit;
		memset(sbuf, 0, 1024);
		// for now, the server echoes all messages twice
		dprintf(conn_fd, "%s\n%s\n", sbuf, sbuf);
		goto thread_exit;
	}

thread_exit:
	ret = close(conn_fd);
	online_users.erase(uname_s);
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

