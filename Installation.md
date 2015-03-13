# Installation #

The load balancer and filter modules has to be compiled into nginx as every other nginx modules:

```
./configure ... --add-module=path/to/sticky --add-module=path/to/lbfilter
make && make install
```

# Usage #

Once installed, the load balancer can be used on an upstream block using the session\_sticky directive in the upstream block of Nginx configuration file.

Eg:
```
upstream backend {
        session_sticky name=jsessionid expires=2h;
        server localhost:8080;
        server localhost:8081;
    }
```

# Syntax #

The session\_sticky directive/command takes 3 parameters to configure the behavior of the load balancing module.

  1. name : is the name of the url parameter that the backend server uses to identify session.
  1. expires : the amount of time after which the session expires and selecting the backend server for that session id is not required anymore.
  1. no\_fallback : When this flag is set, nginx will return a 502 (Bad Gateway orProxy Error) if a request comes with a session id and the corresponding mapped backend is unavailable.

```
session_sticky [name=jsessionid] [expires=1h] [no_fallback];
```