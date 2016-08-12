SERVER = server
CLIENT = client
COMMON = common

CC_FLAGS =  -L/usr/lib -lssl -lcrypto -Wall

all: $(CLIENT) $(SERVER) 

$(SERVER): $(SERVER).c $(COMMON).c
	gcc $^ $(CC_FLAGS) -o $@

$(CLIENT): $(CLIENT).c $(COMMON).c
	gcc $^ $(CC_FLAGS) -o $@

PHONY: .clean

clean:
	rm -f *.o *.h.gch $(SERVER) $(CLIENT) 
