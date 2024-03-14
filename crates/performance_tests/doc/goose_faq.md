# Goose configuration FAQ

This document is by no means a comprehensive guide for Goose.
For details on Goose, run `cargo run --release --bin loadtest -- -h` to get the list of configurable options,
or read the [Goose docs](https://docs.rs/goose/latest/goose/).

For our overrides consult `bin/loadtest.rs` and look for `set_default`.

Goose options are either set in our code, or can be overridden via command line options.
There are not to be confused with the options set via the [`CONFIG`](loadtest_config.md)


## What are some of the Goose defaults we use?

- default test runtime is `120 seconds`
- default warmup time is `5 seconds`
- we run `5` concurrent/parallel clients

## How many times do we run the Goose framework?

We run the test framework twice. Once for `baseline`/`URL1` and once for `new`/`URL2`.

Each run of the framework is a complete Goose run against a different `host` specified by the above mentioned URLs.

## What scenarios exist?

Run `cargo run --bin loadtest --release -- --scenarios-list` or see the source `bin/loadtest.rs`

## Why can't I run multiple scenarios at the same time?

Goose runs ALL scenarios at the same time based on some ratio.
It is designed to run various concurrent workloads against the same server.
Such as `clients`, `admins` and `background` tasks.
This does not work with our infrastructure since we only really have one type of server connection.
As such, only one scenario should be selected.

There are advanced use cases during which the operator might want to run a mix of various scenarios.

## Why can't I run both client scenarios and keyserver scenarios at the same time?

Same answer as above.
Goose runs all selected scenarios against one server.
As such, scenarios meant for different server types would just fail.

## How long should my test run for?

This is actually a tricky question.
The default runtime is 120 seconds, which is not sufficient for large payloads or large numbers of users.

The best way to pick the correct runtime is to run the default and look at the Goose logs:
```
 === PER REQUEST METRICS ===
 ------------------------------------------------------------------------------
 Name                     |        # reqs |        # fails |    req/s |  fail/s
 ------------------------------------------------------------------------------
 POST v3/screen           |            52 |         0 (0%) |     0.43 |    0.00
 ------------------------------------------------------------------------------
 Name                     |    Avg (ms) |        Min |         Max |     Median
 ------------------------------------------------------------------------------
 POST v3/screen           |       12445 |      4,725 |      26,663 |     11,000
 ------------------------------------------------------------------------------
```

In this example we see that the request was answered `52` times and the average request time was `12445ms`.

These values are good.
When running the test, one should make sure that there are at least 50+ runs.

With larger payloads or many users, the response time often reaches 12-30 seconds.
The easy way to estimate a reasonable runtime is to look at the req/s and calculate accordingly.

One does *NOT* need to change the code to change the runtime.
It can be done by specifying `-t <runtime>` in the Goose config.
For example: `cargo run --release --bin loadtest -- --scenarios 3 -t120`
