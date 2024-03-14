# SecureDNA API test framework, built around Goose.

##  Overview

This tool is meant to compare two servers.
It can either be used to extract real measurements from `staging`.
Or to determine whether a feature changes the behavior of the system in a desirable way.

To run a test, the operator needs to do three distinct steps:
1) Pick 2 `servers` which will be compared. 
This framework is meant for comparison purposes and as such, there is always as `baseline` and a `new`.
A `server` can be a local binary, a docker image or any of the production servers such as `demo.staging.securedna.org`. 
Note: Don't run a large load test against `prod` as it might overload the servers and impact customer experience. 
2) Pick a `scenario`.
By default, Goose runs all tests (scenarios) against both provided `servers`.
That is not desirable as some scenarios are meant for HDB, some for KS and some for the client.
3) Look at the results from the `analyzer`.
This tool allows you to extract useful data out of the massive goose output on a single page.

It is also possible to run the perf test in `BaselineOnly` mode, which is described later in this document.

Make sure to read our [Goose FAQ](doc/goose_faq.md).

## 1) Running the load test framework

By default, the framework is given two servers to allow comparing the results.

All configuration is done via a `config.json` file which is expected to exist in the main directory.
The location can be overriden using the `CONFIG` env variable such as:
```
CONFIG=<your-config-file> cargo run ...
```

The config file format is documented further in [`doc/loadtest_config.md`](doc/loadtest_config.md)

The list of available config parameters can be found in the `config.json.example` default configuration file.

Two variables must always be set regardless of whether the operator uses the docker config or self managed config.
`URL1` and `URL2`.
These have to point to the correct type of server for the scenario.

### 1a) Running with self-managed servers

If the operator wishes to test a remote server, a server that is already running (whether locally or on localhost),
no additional configuration is needed.

The operator is responsible for the lifetime of the server components.

### 1b) Running with automated management of docker images

If either of `hdbservers`, `keyserver`, or `clients` is specified, local Docker images will be started for the various server components.
The test framework will kill any existing docker containers to prevent weirdness with leftover processes.

We specify some reasonable defaults such as ports, docker images names and tags.
All can be overriden in the config file.

For more info see the `config.json.example-*-localhost` files.

### Commands

To run: 
```
cargo run --release --bin loadtest -- [Goose options]
```

The test will run for 30 seconds by default, using 5 concurrent users hitting a specific REST API endpoint.
When completed, a new result directory will be created in `../results`.

Note: do not compare a local server to a remote server such as `staging` as this will yield useless results.

## 2) Selecting a scenario

The test framework is a wrapper around the Goose framework.
As such, it is not viable to use something like `clap` to generate the command line arguments.
We pass most arguments to the Goose framework.

To run a test, you have to provide the runner with a scenario such as `ClientRandomSequence` via the `--scenarios` option.
Always pick exactly 1.
The URLs need to be set accordingly to the scenario selected.


The full command would look like this:
```
cargo run --release --bin loadtest -- --scenarios <scenario>
```

For more details on Goose options, check the following output locally:

```
cargo run --release --bin loadtest -- -h
```

## 3) Run the analyzer
The analyzer is being run automatically after each run.

The analyzer will spit out some stats such as:
```
Writing CSV file to: results/<id>/summary.csv
-----------------------------------------
Config
Baseline URL: https://1.db.staging.securedna.org
New URL: https://1.db.staging.securedna.org
-----------------------------------------
Stat      Baseline  New       Difference%
-----------------------------------------
Throughput
hash_s    25263.67  25628.82  1.45      %
bp_s      7549.49   7658.61   1.45      %
-----------------------------------------
Latency
mean_ms   202.66    199.78    -1.42     %
min_ms    0.00      0.00      NaN       %
max_ms    1111.00   1516.00   36.45     %
spread    1111.00   1516.00   36.45     %
stdev     84.30     79.21     -6.04     %
variance  7106.88   6273.66   -11.72    %

```

The most important stat is the first row (`mean`) which indicates the mean `ms` per request.
Each request is one run of the `scenario` requested above and can be something like:

```
ClientRandomSequence
> This scenario should be executed against two running synthclients
> This scenario generates a random payload and runs it against URL1/screen and URL2/screen
> Each payload in this scenario is 2000 random base pairs
> The scenario runs on 5 clients and has a duration of 30 seconds
```

All aspects of a scenario are hardcoded and cannot be configured.

## 4) Interpreting results

The main measurement of Goose is the `latency` in `milliseconds`.
It indicates how long, on average, a request took to answer.
In addition, this framework also understands and reports two other measurements, `HashRate (hash/s)` and `BasePairs per second (bp/s)`.
It has been decided that the `HashRate` (aka number of 32B hashes/windows per second) is the standard unit of measurement.

To convert between `BPs` and `Hashes` one needs to follow the formula `BP_Count = (HashCount+258)/6`.
In all tests, the standard size of a request is 5742 Hashes or 2000 BPs.

To convert from `milliseconds` to `HR` one needs to follow the formula `HR = 1/<ms> * <nr_of_client_threads> * <size_of_request_in_hashes>`.
For all of our tests there are 5 clients and 5742Hashes/request hence the formula for conversion is:
```
HR = 1000/<latency in ms> * 5 * 5742
```

The conversion between all units is done automatically by the `analyzer` crate.

## Nightly Time Series Results

To observe changes over time, the framework can be run nightly against the current branch (ideally main) and collect runtimes into a time series.

To do so, we are using Prometheus Gateway.
To enable the prometheus metrics collection, set `PUSH_METRICS` to `TRUE`.
The operator is expected to setup a correctly set up prometheus gateway on the performance machine.
By default, we expect the gateway to listen on `localhost:9091`.

Do not enable collection of private branches on the performance machines.
If you wish to do so, set up your own Prometheus.

## Baseline Only Mode
In general, the framework is designed to get comparison between two configs, two servers or two configurations.
But often operators want to use it to just get one number, such as "the current staging", without comparing it.

This can be achieved by setting `comparison_mode` to `BaseOnly`.
One can leave `URL2` empty as well.

For example:
```json
{
  "url1": "https://demo.staging.securedna.org",
  "comparison_mode": "BaseOnly"
}
```

As a result, the framework will run just once and print no comparison such as:
```
Stat      Baseline
-----------------------------------------
Throughput
hash_s    2192.99
bp_s      439.28
-----------------------------------------
Latency
mean_ms   2913.83
min_ms    1459.00
max_ms    5497.00
spread    4038.00
-----------------------------------------
Failure Rate
fail_rt   0.00
```
