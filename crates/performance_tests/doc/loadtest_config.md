# Load test config file

This file documents the `config.json` file required by the performance framework.

This is a manually generated file and might get out of sync with the corresponding source at `shared/config.rs`.
Should that happen, refer to the source.

## Caveat

To run the framework, one must both supply the config file and provide exactly 1 scenario to the underlying Goose framework.
This might be slightly confusing since both are not configured at the same location.

For details on Goose, run `cargo run --release --bin loadtest -- -h` to get the list of configurable options,
or read the [Goose docs](https://docs.rs/goose/latest/goose/).

## URLs

The framework is designed to compare to servers against each other. `URL1` vs `URL2`.
These values must be set for all tests.

As such, the minimal configuration file is:
```json
{
  "url1": "<server1>",
  "url2": "<server2>"
}
```

`url2` can be left unset if `comparison_mode` is set to `BaseOnly`.

Additional options:
- `hash_count`: override the size of the request. The default is `5742`. It is recommended that overrides are divisible by 6. Can also be overriden using the SECUREDNA_HASH_COUNT env variable.
- `comparison_mode`: can be set to `BaseOnly` to only run one set of tests without comparing against `url2`. The default is `Comparison`.
- `auth_key`: deprecated from synthclient API. TODO: Perf test framework must be updated for latest synthclient.
- `api_version_*`: generally not required to override. Default is the current API version. Only required if testing older code which has a different API version. Api1 was pre-compressed-ristrettos.
- `pushgateway_url`: Override the Grafana/Prometheus setup. Do not touch unless you know what you are doing. Works in conjunction with `PUSH_METRICS`.
- `network_name`: Override the docker network used for testing. Defaults to `securedna-loadtest-network`

## Using automated management of docker servers

If the operator wishes to use manual server management, this section can be skipped.

To start a set of keyservers specify:
```json
{
  ...
  "keyservers": {
    ...
  },
  ... or ...
  "clients": {
    ...
  },
  ... or ...
  "hdbservers": {
    ...
  },
}
```

Usually you might only want of the three types for testing.
But if you want to start the full stack locally, you can.

### Common config options for clients, KSs and HDB

The options are always prefixed with the type of server, but the prefix will be omitted here.
`port` would have to be `client_port`, `keyserver_port`, or `hdbserver_port`.

- `port`: specifies the external/exposed ports to be used for the managed servers. Two ports will be used. `port` and `port+1`. `port` is used for `base` and `port+1` is used for `new`. These ports should be specified in the general config as URL1 and URL2. Usually `port` becomes `URL1` and `port+1` becomes `URL2`.
- `port_internal_base` and `port_internal_new`: specify the port of the process inside of the docker container. 
- Since `0.2.1` it's always 80 and does not need to be specified. But in `0.1` and prior it was not consistent. Consult the `Earthfile` of the version you are testing to determine the correct internal port.
- `repo_base` and `repo_new`: This is usually `ghcr.io/securedna/<servertype>` and does not need to be overridden. Override this if using custom image tags not produced by Earthly.
- `repo_tag_base` and `repo_tag_new`: the tag of the docker image. This is probably the option you will be overriding the most. The default is `latest` which will use the latest image present on the test machine. This uses the pull strategy `ifNotPresent` and will NOT automatically download a new version from the remote registry. The SHA is generally the first 8 characters of the git commit, if downloaded from remote. For images built locally, it can be anything the operator specifies. As a recommendation, use the latest commit in main present in the tested branch as `base` and `latest` for `new`.
- `cpu_limit`: limits the number of CPUs via docker `--cpus`

### Keyserver specific options

- `keyserver_keyshare`: The keyshare to be used. The same value is used by both `new` and `baseline`. Required option.
- `keyserver_id`: The keyserver id to be used. The same value is used by both `new` and `baseline`. Required option.

### Client specific options

- `client_hdbservers`: Which HDB server domains to use. Defaults to the `staging` set. If the framework starts all three types you can use `<keyserver>` magic template value to autodetect the keyserver. 
- `client_keyservers`: Which keyserver domains to use. Defaults to the `staging` set. If the framework starts all three types you can use `<hdbserver>` magic template value to autodetect the hdbserver.
- `client_override_ops`: If everything else fails, you can use this to configure the client. This option will most likely force you to use `BaseOnly` since the magic detection will be broken.

It is up to the operator to decide how they want to test the client.
Client is tricky since it depends on the performance of keyservers and hdb servers.
On top of that, the absolute numbers will depend on the network infrastructure between the tested clients and the other components.
It is recommended to test against staging to avoid CPU congestion on the test machine.
In general, only the tested component and the test framework should run on the test host.

### HDB specific options

- `hdb_vol`: The HDB directory. Required option.

Running a local HDB comparison can be tricky if `new` and `base` use a different HDB format.
Such values are generally not apples/apples comparisons since the DB is different.
The same DB should be used for all HDB performance comparisons.
If one wants to compare 2 HDBs, run the test once with base code and base HDB and then run it again with new HDB and new code.
This will not help you isolate whether the performance changes are caused by a different DB or different code, but it gives a good base for investigation.
