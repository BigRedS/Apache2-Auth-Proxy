Apache2::Auth::Proxy
====================

Description
-----------

Sometimes you have a single HTTP-Auth protected system somewhere and wish to use the same 
usernames and passwords on some other systems. You may do this by implementing a single-sign-on 
system, or perhaps with a lot of cronned SCPs. You might also do that with this module.


This module handles HTTP auth and uses a different URI's HTTP auth as its backend - if a username 
and password pair will grant access to that URI, then it will be allowed in here. In this instance, 
the username and password are written to a htpasswd file locally and kept as a cache. Future 
lookups then don't require the additional HTTP requests. At some point soon this cache will support 
the notion of expiry.
