# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic -pthread

# Targets
SERVER_SRC = server_grp.cpp
CLIENT_SRC = client_grp.cpp
SERVER_BIN = server_grp
CLIENT_BIN = client_grp
CUSTOM_CLIENT_SRC = custom_client.cpp
CUSTOM_CLIENT = custom_client


# Default target
all: $(SERVER_BIN) $(CLIENT_BIN) $(CUSTOM_CLIENT)

# Compile server
$(SERVER_BIN): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $(SERVER_BIN) $(SERVER_SRC)

# Compile client
$(CLIENT_BIN): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $(CLIENT_BIN) $(CLIENT_SRC)

# Added in our submission: compile the custom client
$(CUSTOM_CLIENT): $(CUSTOM_CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $(CUSTOM_CLIENT) $(CUSTOM_CLIENT_SRC)

# Clean build artifacts
clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN) a.out $(CUSTOM_CLIENT)

