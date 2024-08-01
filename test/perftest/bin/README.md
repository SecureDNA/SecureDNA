Prerequisites:

* Linux.  This has not been tested in any other operating system or on
  non-POSIX filesystems.  It assumes that `cwd` does not have spaces
  or shell metacharacters in it, and it depends on Linux interfaces
  such as `/proc/PID/stat`.  It also assumes that you have `bash` and
  that `bash` can use 64-bit arithmetic.
* `docker`
* `docker-tc` (optional, if running test with delays.  See https://github.com/lukaszlach/docker-tc)
* `moreutils`, for `ts` (optional; used only in timestamping logs)

In bash, do `export mygit=SOMEPLACE`, `cd $mygit`, then `git clone
git@github.com:SecureDNA/SecureDNA`.  Note that, unless you want to
change the number of keyservers, you do *not* need to have a working
Rust toolchain or build anything in the repo; you'll only be using
some of its config files.

Source `test/bin/run-tests` and then run `perf/init` once.

After that, you can use `perf/run` to run all test without delays,
or `perf/delaytop` to run tests with delays.  You can also use
`perf/delaytop` to run both, if you change `perf_delays=( 100 )`
to `perf_delays=( 0 100 )`.  To abort in the middle, use `perf/abort`,
which will terminate the next time a new set of containers is about to
be brought up.  (Use `perf/unabort` to reset.)

If you want to change the number of keyservers, you must have a Rust
toolchain installed and build the system, after which you must ensure
that `genkeyshares` and `genactivesecuritykey` are in your `PATH`.
At that point, change the value of `perf_ks_numbers` and run both
`perf/dock-all` and `perf/toml-all` to regenerate the various `.yml`
and `.toml` files, whereupon you can use `perf/run` or `perf/delaytop`
as above.
