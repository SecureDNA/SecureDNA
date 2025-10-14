This directory holds both the public and the private portions of a set
of *test* certificates.  They're generated from testing tools, they're
expendable, they may be replaced at any time by a new commit, and they
are useless for production because the production servers don't use
these roots, hence any cert or token from this directory cannot be
used to authenticate to a production server.  Thus, it's safe for them
to be accompanied by their private keys and passphrases and released
to the public.
