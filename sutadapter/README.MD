The TCP SUT can be run using one of the two SUT adapters provided.

- *server adapter* (`serverAdapter.py`) implements a sequential TCP echo server.
- *socket adapter* (`socketAdapter.c`) implements a command server that can be commanded to launch TCP clients/servers and call on them socket calls

# Building
To build the socket adapter
on Linux: 
```
open a terminal
gcc -Wall -pthread -o serverAdapter.o serverAdapter.c
```

on Windows:
```
open a developer command prompt (should come with VS)
cl serverAdapter.c
```

# Running
```
sudo nice -19 ./socketAdapter.o -a 192.168.56.104 -l 5000 -p 20000
```

    
