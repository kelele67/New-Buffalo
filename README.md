# BUFFALO

refactor the [buffalo](https://github.com/kelele67/Buffalo) code

Build status:
![](https://img.shields.io/scrutinizer/build/g/filp/whoops.svg)
![](https://img.shields.io/github/license/mashape/apistatus.svg)

Buffalo is a fast and lightweight Web Server for the Linux platform.

 It is based on the RFC2616 document corresponding to the specification
 HTTP/1.1 protocol.

>Learn from opensource projects: Apache Nginx Libevent Monkey...


## Features

* - HTTP/1.1 Compliant
* - Hybrid Networking Model: Asynchronous mode + fixed Threads
* - Easy unix style configuration
* - Virtual Hosts
* - Pipelining
* - Resume of connections
* - Server user's home directories
* - Log files --TODO
* - Versatile plugin subsystem

## Install

>For optimum performance, I recommend that Buffalo be compiled with GCC >= 
2.95.3 and be running on a Linux OS with kernel >= 2.6.28.
Like every source program we must run 'configure' script and later
 'make':

```shell
$ ./configure
$ make 
```
---

## Running

```shell
    bin/buffalo
```
---

    or

```shell
    bin/buffalo -D (to run buffalo in background mode)
```
---

 Optionally, you can specify the directory where the configuration files
 are found, this can be done the following way: 

```shell
    bin/buffalo -D -c conf/
```
---

 This argument (conf/) was thought of for those wishing to have Buffalo
 running for various users, in distinctive Ports and it's own 
 configuration files. For more information see 'conf/buffalo.conf'.

 For more info try -h option.

## Testing

To see that Buffalo is running, make a request from a browser, like lynx
or netscape:
 
    # lynx 127.0.0.1:2017
    
 Note: In this example the '2017' corresponds to the connection port
 assigned on 'conf/buffalo.conf'.