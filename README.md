Sticky session load balancer module for Nginx
=======================

Blog Link :: https://saigopal.com/blog/nginx

When using a fair load balancer, maintaining client state on server becomes a problem as each request could go to a different back end server.

For eg : request 1 could go to server x. Server x has created a session for the client and stored the session data in its memory. But the 2nd request from the client could go to a server Y due to the load balancer.

This project is an Nginx load balancer module desgined to solve exactly the problem mentioned above. It also has an associated filter module to help support the load balncer.

It does this by maintaining a mapping of the session id(name is configurable) generated in response html to the backend server it came from.
Further requests with that session id in the url will be forwarded to the mapped back end server until the session has expired(expiry time is configurable).

When there is no mapping or if the url does not have session id, it uses classic round robin to select backend server.

Note : New mappings are created and added into the map only from the response html's form action url.


## summary Installation and usage of this module

### Installation

The load balancer and filter modules has to be compiled into nginx as every other nginx modules:

```
./configure ... --add-module=path/to/sticky --add-module=path/to/lbfilter
make && make install
```

###Usage

Once installed, the load balancer can be used on an upstream block using the session_sticky directive in the upstream block of Nginx configuration file.

Eg:
```
upstream backend {
        session_sticky name=jsessionid expires=2h;
        server localhost:8080;
        server localhost:8081;
    }
 ```
### Syntax

The session_sticky directive/command takes 3 parameters to configure the behavior of the load balancing module.

  - # name : is the name of the url parameter that the backend server uses to identify session.
  - # expires : the amount of time after which the session expires and selecting the backend server for that session id is not required anymore.
  - # no_fallback : When this flag is set, nginx will return a 502 (Bad Gateway orProxy Error) if a request comes with a session id and the corresponding mapped backend is unavailable.

```
session_sticky [name=jsessionid] [expires=1h] [no_fallback];
```
