# MDB

Some blog thing. Posts are written in markdown and put in posts/

Run sign.sh to generate PGP detached signatures which are linked to at the bottom of every post

The code tries to limit access to inside the website directory (hardcoded in the code at the moment). I'm confident there
are no directory traversal attacks directly.

Users are not stored between runs, and the is no way to add new users, and users can't do anything at the moment. The code uses
pbkdf2_hmac and sha256, a 32 byte salt from /dev/urandom and 1 000 000 iterations. This takes about a second on my machine.  
There is no current protection against a DoS by just forcing the server to generate hashes continously. I've found it only takes 6 processes
hitting the authenticate page to make the website completely unusable. This could be mitigated by a proof of work on the client machine
(requires javascript), or locking the IP out after x amount of incorrect guesses(doesn't work well against people with access to many IP's)
