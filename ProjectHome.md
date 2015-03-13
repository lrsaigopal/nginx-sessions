When using a fair load balancer, maintaining client state on server becomes a problem as each request could go to a different back end server.

For eg : request 1 could go to server x. Server x has created a session for the client and stored the session data in its memory. But the 2nd request from the client could go to a server Y due to the load balancer.

This project is an Nginx load balancer module desgined to solve exactly the problem mentioned above. It also has an associated filter module to help support the load balncer.

It does this by maintaining a mapping of the session id(name is configurable) generated in response html to the backend server it came from.
Further requests with that session id in the url will be forwarded to the mapped back end server until the session has expired(expiry time is configurable).

When there is no mapping or if the url does not have session id, it uses classic round robin to select backend server.

**Note : New mappings are created and added into the map only from the response html's form action url.**