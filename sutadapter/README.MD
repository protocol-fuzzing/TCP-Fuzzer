# Building
To build the server adapter
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


    
