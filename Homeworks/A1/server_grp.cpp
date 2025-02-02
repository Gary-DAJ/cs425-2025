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

using namespace std;

unordered_map<int, string> clients; // Client socket -> username
unordered_map<string, string> users; // Username -> password
unordered_map<string, unordered_set<int>> groups; // Group -> client sockets

// General APIs needed:
int do_auth(string username, string password);
void private_message(int client_socket, string user_name, string pvt_msg);
void broadcast_message(int client_socket, string msg);
void create_group(int client_socket, string group_name){
    groups[group_name] = unordered_set<int>();
    groups[group_name].insert(client_socket);
    // broadcast_message(-1, "Group created - "+group_name);
}
void user_exit(int client_socket, string username);
void join_group(int client_socket, string group_name){
    if(groups.find(group_name)==groups.end()){
        // private_message(-1, clients[client_socket], "Group not found!");
    }else{
        groups[group_name].insert(client_socket);
        // group_message(-1, group_name, clients[client_socket] + " - joined the group - " << group_name << "\n");
    }
}
void group_message(int client_socket, string group_name, string group_msg){
    if(groups.find(group_name)==groups.end()){
        // private_message(-1, clients[client_socket], "Group not found!");
    }else{
        string message = "["+group_name+"]: " + (client_socket==-1?"":
                        "["+clients[client_socket]+"]: ") + group_msg;
        for(int sock : groups[group_name]){
            //
        }
    }
}
void leave_group(int client_socket, string group_name){
    if(groups.find(group_name)==groups.end()){
        // private_message(-1, clients[client_socket], "Group not found!");
    }else if(groups[group_name].erase(client_socket)){
        // group_message(-1, group_name, clients[client_socket] + " - left the group - " << group_name << "\n");
        // private_message(-1, clients[client_socket], "You left the group - "+group_name);
    }else{
        // private_message(-1, clients[client_socket], "You were not a part of that group!");
    }
}

int do_auth(string username, string password)
{
    if (users.find(username) != users.end()) {
        if (users[username] == password) {
            return 0;
        }
    }
    return -1;
}

void private_message(int client_socket, string user_name, string pvt_msg) {
	return ;
}

void broadcast_message(int client_socket, string msg) {
	return ;
}

void user_exit(int socket, string username) {
};

int process_client_message(char *buf){
    string message = buf;
    int client_socket = 1;
    if(message.starts_with("/msg")){
        size_t space1 = message.find(' ');
        size_t space2 = message.find (' ', space1 + 1);
        if(space1 != string::npos && space2 != string::npos){
            string user_name = message.substr(space1 + 1, space2 - space1 - 1);
            string pvt_msg = message.substr(space2 + 1);
            private_message(client_socket, user_name, pvt_msg);
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
	    printf("[server] can't understand message\n%s\n", buf);
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
	cout << sbuf << endl;

	char auth2[] = "Enter password: ";
	ret = write(conn_fd, auth1, strlen(auth1) + 1);
	cout << "server sent bytes " << ret << " to FD " << conn_fd << endl;
	assert(ret == 17);
	ret = read(conn_fd, password, 64);
	assert(ret < 63);
	cout << "server received bytes: " << ret << " from FD " << conn_fd << endl;
	cout << sbuf << endl;

	ret = do_auth(username, password);
	if (ret == -1) {
		dprintf(conn_fd, "Authentication failed");
		goto thread_exit;
	}
	ret = dprintf(conn_fd, "Authentication successful");
	assert (ret > 10);

	while (1) {
		ret = read(conn_fd, sbuf, 1024);
		if (ret <= 0) {
			printf("[server] looks like user %s left\n", username);
			goto thread_exit;
		}
		printf("server received message from %s: (%d)\n%s\n\n", username, ret, sbuf);
		ret = process_client_message(&sbuf[0]);
		if (ret == 1)
			goto thread_exit;
		memset(sbuf, 0, 1024);
		// for now, the server echoes all messages twice
		dprintf(conn_fd, "%s\n%s\n", sbuf, sbuf);
		goto thread_exit;
	}

thread_exit:
	ret = close(conn_fd);
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

