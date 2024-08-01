This directory holds the TOML configuration files necessary to run
performance tests across variable numbers of keyservers.  For an
explanation of what the parameters mean, consult the `database.toml`
file, which has comments describing them.

The first two digits of `nn.keyserver-mm.toml` describe how large the
set of keyservers is in this batch; these tests always assume that the
quorum is exactly as large as that set, e.g., you must always use `n`
out of `n` keyservers.  The trailing two digits describe, for this
batch, which keysever this is.  Thus, a batch which requires three
keyservres would consist of '03.keyserver-01.toml',
'03.keyserver-02.toml', and '03.keyserver-03.toml'.

The relevant `docker-compose` files are found in `../perftest/config/`,
generated via template subsitution from `../perftest/templates/`.
