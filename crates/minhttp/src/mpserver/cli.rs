// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`clap`]-compatible type for reading server configs from CLI args or TOML files.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{ArgMatches, Args, Command, FromArgMatches};
use futures::future::{Either, TryFutureExt};
use serde::Deserialize;

use super::common::{stub_cfg, toml_reader};
use super::tls::TlsConfig;
use super::traits::{AppConfig, LoadConfigFn, RelativeConfig};
use super::{PlaneConfig, ServerConfig};
use crate::error::ErrWrapper;

/// [`clap`]-compatible struct that accepts either a config path or configuration options.
///
/// This can be flattened into a [`clap::Parser`], in which case it defines all the command-line
/// arguments for runing a server (with application-specific arguments obtained from the generic
/// parameter `AC`), and supplies a [`into_load_cfg_fn`](Self::into_load_cfg_fn) that populates
/// the config from the CLI options or TOML config as appropriate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerConfigSource<AC> {
    Path(PathBuf),
    Value(Box<ServerConfig<AC>>),
}

// Unfortunately, this needs to stay synced with minhttp::mpserver::server::{ServerConfig, PlaneConfig}
#[derive(Args, Clone, Debug)]
struct MultiplaneOpts<AC: Args> {
    #[arg(
        long,
        env = "SECUREDNA_CFG_PATH",
        help = "The path to the server config TOML",
        exclusive = true
    )]
    cfg_path: Option<PathBuf>,

    #[arg(
        short,
        long,
        env = "SECUREDNA_PORT",
        help = "Address to listen on for main plane; if only a port is specified, all IPv4 addresses are used.",
        value_parser = parse_port_or_socket_addr,
        default_value = "80"
    )]
    pub port: Option<SocketAddr>,

    #[arg(
        requires = "tls_certificate",
        long,
        env = "SECUREDNA_TLS_PORT",
        help = "Address to listen on for TLS main plane; if only a port is specified, all IPv4 addresses are used.  Defaults to 443 if TLS certs are supplied.",
        value_parser = parse_port_or_socket_addr
    )]
    pub tls_port: Option<SocketAddr>,

    #[arg(
        long,
        help = "Maximum simultaneous connections to main plane that may be accepted before the server returns 503.",
        env = "SECUREDNA_MAX_CONNECTIONS",
        default_value_t = PlaneConfig::default_max_connections(),
    )]
    pub max_connections: u32,

    #[arg(
        requires = "tls_private_key",
        long,
        env = "SECUREDNA_TLS_CERTIFICATE",
        help = "Certificate for enabling TLS"
    )]
    pub tls_certificate: Option<PathBuf>,

    #[arg(
        requires = "tls_certificate",
        long,
        env = "SECUREDNA_TLS_PRIVATE_KEY",
        help = "Private key for enabling TLS"
    )]
    pub tls_private_key: Option<PathBuf>,

    #[arg(
        long,
        env = "SECUREDNA_MONITORING_PORT",
        help = "Address to listen on for monitoring plane; if only a port is specified, all IPv4 addresses are used.",
        value_parser = parse_port_or_socket_addr
    )]
    pub monitoring_port: Option<SocketAddr>,

    #[arg(
        requires = "tls_certificate",
        long,
        env = "SECUREDNA_MONITORING_TLS_PORT",
        help = "Address to listen on for monitoring TLS plane; if only a port is specified, all IPv4 addresses are used.",
        value_parser = parse_port_or_socket_addr
    )]
    pub monitoring_tls_port: Option<SocketAddr>,

    #[arg(
        long,
        help = "Maximum simultaneous connections to monitoring plane that may be accepted before the server returns 503.",
        env = "SECUREDNA_MONITORING_MAX_CONNECTIONS",
        default_value_t = PlaneConfig::default_max_connections(),
    )]
    pub monitoring_max_connections: u32,

    #[arg(
        long,
        env = "SECUREDNA_CONTROL_PORT",
        help = "Address to listen on for control plane; if only a port is specified, all IPv4 addresses are used.",
        value_parser = parse_port_or_socket_addr
    )]
    pub control_port: Option<SocketAddr>,

    #[arg(
        requires = "tls_certificate",
        long,
        env = "SECUREDNA_CONTROL_TLS_PORT",
        help = "Address to listen on for control TLS plane; if only a port is specified, all IPv4 addresses are used.",
        value_parser = parse_port_or_socket_addr
    )]
    pub control_tls_port: Option<SocketAddr>,

    #[arg(
        long,
        help = "Maximum simultaneous connections to control plane that may be accepted before the server returns 503.",
        env = "SECUREDNA_CONTROL_MAX_CONNECTIONS",
        default_value_t = PlaneConfig::default_max_connections(),
    )]
    pub control_max_connections: u32,

    #[command(flatten)]
    pub app_cfg: Option<AC>,
}

impl<AC> ServerConfigSource<AC> {
    /// Converts this [`ServerConfigSource`] into a [`LoadConfigFn`] implementation.
    pub fn into_load_cfg_fn(self) -> impl LoadConfigFn<ServerConfig<AC>, Error = ErrWrapper>
    where
        AC: Clone + AppConfig + RelativeConfig + for<'a> Deserialize<'a>,
    {
        let load_cfg_fn = match self {
            Self::Path(cfg_path) => Either::Left(toml_reader(cfg_path)),
            Self::Value(server_cfg) => {
                let load_cfg = stub_cfg(move || (*server_cfg).clone());
                // convert err so branches produce compatible LoadConfigFn types
                let load_cfg = || load_cfg().map_err(Into::into);
                Either::Right(load_cfg)
            }
        };

        // `Either` will handle unifying `Future` types, but we need to invoke each branch's function.
        move || match load_cfg_fn {
            Either::Left(f) => Either::Left(f()),
            Either::Right(f) => Either::Right(f()),
        }
    }
}

impl<AC: Args> FromArgMatches for ServerConfigSource<AC> {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let opts = MultiplaneOpts::<AC>::from_arg_matches(matches)?;
        if let Some(path) = opts.cfg_path {
            assert!(opts.monitoring_port.is_none());
            assert!(opts.control_port.is_none());
            assert!(opts.app_cfg.is_none());
            Ok(Self::Path(path))
        } else {
            let app_cfg = match opts.app_cfg {
                Some(app_cfg) => app_cfg,
                // If T has no required arguments, then opts.app_cfg is None. :(
                None => AC::from_arg_matches(matches)?,
            };

            // TODO: maybe require (port or tls_port) for max_connections?
            //return Err(clap::Error::new(clap::error::ErrorKind::ValueValidation));

            let cert = opts.tls_certificate;
            let key = opts.tls_private_key;
            let tls_config_for_port = |port| maybe_tls_config(cert.clone(), key.clone(), port);

            let main_tls_port = opts.tls_port.or(Some("0.0.0.0:443".parse().unwrap()));
            let main = PlaneConfig {
                address: opts.port,
                tls_config: tls_config_for_port(main_tls_port),
                max_connections: opts.max_connections,
                custom: app_cfg,
            };
            let monitoring = PlaneConfig {
                address: opts.monitoring_port,
                tls_config: tls_config_for_port(opts.monitoring_tls_port),
                max_connections: opts.monitoring_max_connections,
                custom: (),
            };
            let control = PlaneConfig {
                address: opts.control_port,
                tls_config: tls_config_for_port(opts.control_tls_port),
                max_connections: opts.control_max_connections,
                custom: (),
            };
            let server_config = ServerConfig {
                main,
                monitoring,
                control,
            };

            Ok(Self::Value(Box::new(server_config)))
        }
    }

    fn update_from_arg_matches(&mut self, _matches: &ArgMatches) -> Result<(), clap::Error> {
        unimplemented!()
    }
}

impl<AC: Args> Args for ServerConfigSource<AC> {
    fn augment_args(cmd: Command) -> Command {
        MultiplaneOpts::<AC>::augment_args(cmd)
    }

    fn augment_args_for_update(cmd: Command) -> Command {
        MultiplaneOpts::<AC>::augment_args_for_update(cmd)
    }
}

fn parse_port_or_socket_addr(arg: &str) -> Result<SocketAddr, <SocketAddr as FromStr>::Err> {
    match u16::from_str(arg) {
        Ok(port) => Ok(SocketAddr::from(([0, 0, 0, 0], port))),
        Err(_) => SocketAddr::from_str(arg),
    }
}

/// Construct a [`TlsConfig`] if all required arguments are given.
fn maybe_tls_config(
    tls_certificate: Option<PathBuf>,
    tls_private_key: Option<PathBuf>,
    tls_address: Option<SocketAddr>,
) -> Option<TlsConfig> {
    tls_certificate.zip(tls_private_key).zip(tls_address).map(
        |((tls_certificate, tls_private_key), tls_address)| TlsConfig {
            tls_certificate,
            tls_private_key,
            tls_address,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    #[derive(Parser, Clone, Debug, PartialEq, Eq)]
    struct CommandOpts<T: Args> {
        #[command(flatten)]
        cfg_src: ServerConfigSource<T>,
    }

    #[derive(Args, Clone, Debug, PartialEq, Eq)]
    struct Opts {
        #[arg(long)]
        count: Option<u32>,
    }

    fn parse<T: Parser>(args: &[&str]) -> T {
        match T::try_parse_from(args) {
            Ok(x) => x,
            Err(err) => panic!("{err}"),
        }
    }

    fn parse_cfg_value<T: Args>(args: &[&str]) -> ServerConfig<T> {
        let cmd_opts: CommandOpts<T> = parse(args);
        match cmd_opts.cfg_src {
            ServerConfigSource::Path(path) => panic!(
                "Called ServerConfigSource::unwrap_value on a path: {}",
                path.display()
            ),
            ServerConfigSource::Value(server_cfg) => *server_cfg,
        }
    }

    #[test]
    fn test_accepts_cfg_path() {
        let cmd_opts: CommandOpts<Opts> = parse(&["server", "--cfg-path", "foo/bar.toml"]);
        let expected = ServerConfigSource::Path("foo/bar.toml".into());
        assert_eq!(cmd_opts.cfg_src, expected);
    }

    #[test]
    fn test_accepts_minimal_server_settings() {
        let server_cfg: ServerConfig<Opts> = parse_cfg_value(&["server"]);
        assert_eq!(
            server_cfg.main,
            PlaneConfig {
                address: Some("0.0.0.0:80".parse().unwrap()),
                tls_config: None,
                max_connections: PlaneConfig::default_max_connections(),
                custom: Opts { count: None },
            }
        );
        assert!(!server_cfg.monitoring.is_enabled());
        assert!(!server_cfg.control.is_enabled());
    }

    #[test]
    fn test_accepts_addressless_port() {
        let server_cfg: ServerConfig<Opts> = parse_cfg_value(&["server", "-p", "123"]);
        assert_eq!(
            server_cfg.main,
            PlaneConfig {
                address: Some("0.0.0.0:123".parse().unwrap()),
                tls_config: None,
                max_connections: PlaneConfig::default_max_connections(),
                custom: Opts { count: None },
            }
        );
        assert!(!server_cfg.monitoring.is_enabled());
        assert!(!server_cfg.control.is_enabled());
    }

    #[test]
    fn test_accepts_full_address() {
        let server_cfg: ServerConfig<Opts> = parse_cfg_value(&["server", "-p", "2.3.5.7:11"]);
        assert_eq!(
            server_cfg.main,
            PlaneConfig {
                address: Some("2.3.5.7:11".parse().unwrap()),
                tls_config: None,
                max_connections: PlaneConfig::default_max_connections(),
                custom: Opts { count: None },
            }
        );
        assert!(!server_cfg.monitoring.is_enabled());
        assert!(!server_cfg.control.is_enabled());
    }

    #[test]
    fn test_tls_port_defaults_to_443_if_tls_is_enabled() {
        let server_cfg: ServerConfig<Opts> = parse_cfg_value(&[
            "server",
            "--tls-certificate",
            "cert.pem",
            "--tls-private-key",
            "key.pem",
        ]);
        assert_eq!(
            server_cfg.main,
            PlaneConfig {
                address: Some("0.0.0.0:80".parse().unwrap()),
                tls_config: Some(TlsConfig {
                    tls_address: "0.0.0.0:443".parse().unwrap(),
                    tls_certificate: "cert.pem".into(),
                    tls_private_key: "key.pem".into(),
                }),
                max_connections: PlaneConfig::default_max_connections(),
                custom: Opts { count: None },
            }
        );
        assert!(!server_cfg.monitoring.is_enabled());
        assert!(!server_cfg.control.is_enabled());
    }

    #[test]
    fn test_all_server_settings_are_passed_through() {
        let cmd_opts: CommandOpts<Opts> = parse(&[
            "server",
            "--port",
            "1.2.3.4:56",
            "--tls-port",
            "1.2.3.4:569",
            "--max-connections",
            "123",
            "--count",
            "31337",
            "--monitoring-port",
            "2.3.4.5:67",
            "--monitoring-tls-port",
            "2.3.4.5:679",
            "--monitoring-max-connections",
            "234",
            "--control-port",
            "3.4.5.6:78",
            "--control-tls-port",
            "3.4.5.6:789",
            "--control-max-connections",
            "345",
            "--tls-certificate",
            "cert.pem",
            "--tls-private-key",
            "key.pem",
        ]);
        let expected = ServerConfigSource::Value(Box::new(ServerConfig {
            main: PlaneConfig {
                address: Some("1.2.3.4:56".parse().unwrap()),
                tls_config: Some(TlsConfig {
                    tls_address: "1.2.3.4:569".parse().unwrap(),
                    tls_certificate: "cert.pem".into(),
                    tls_private_key: "key.pem".into(),
                }),
                max_connections: 123,
                custom: Opts { count: Some(31337) },
            },
            monitoring: PlaneConfig {
                address: Some("2.3.4.5:67".parse().unwrap()),
                tls_config: Some(TlsConfig {
                    tls_address: "2.3.4.5:679".parse().unwrap(),
                    tls_certificate: "cert.pem".into(),
                    tls_private_key: "key.pem".into(),
                }),
                max_connections: 234,
                custom: (),
            },
            control: PlaneConfig {
                address: Some("3.4.5.6:78".parse().unwrap()),
                tls_config: Some(TlsConfig {
                    tls_address: "3.4.5.6:789".parse().unwrap(),
                    tls_certificate: "cert.pem".into(),
                    tls_private_key: "key.pem".into(),
                }),
                max_connections: 345,
                custom: (),
            },
        }));
        assert_eq!(cmd_opts.cfg_src, expected);
    }

    #[test]
    fn test_cfg_path_conflicts_with_main_plane() {
        CommandOpts::<Opts>::try_parse_from([
            "server",
            "--cfg-path",
            "foo/bar.toml",
            "--port",
            "0.0.0.0:80",
        ])
        .unwrap_err();
    }

    /*

    // In an ideal world, we'd make max_connections depend on (port or tls_port)
    // but that seems like a pain in clap... for now it's easier to just let people specify
    // max_connections even for disabled planes

    #[test]
    fn monitoring_address_is_required_for_monitoring_max_connections() {
        CommandOpts::<Opts>::try_parse_from([
            "server",
            "--port",
            "0.0.0.0:80",
            "--monitoring-max-connections",
            "123",
        ])
        .unwrap_err();
    }

    #[test]
    fn control_address_is_required_for_control_max_connections() {
        CommandOpts::<Opts>::try_parse_from([
            "server",
            "--port",
            "0.0.0.0:80",
            "--control-max-connections",
            "123",
        ])
        .unwrap_err();
    }

    */

    #[test]
    fn cert_and_private_key_require_each_other() {
        CommandOpts::<Opts>::try_parse_from(["server", "--tls-certificate", "certificate.pem"])
            .unwrap_err();
        CommandOpts::<Opts>::try_parse_from(["server", "--tls-private-key", "private.pem"])
            .unwrap_err();
    }

    #[test]
    fn tls_ports_requires_certificate() {
        CommandOpts::<Opts>::try_parse_from(["server", "--tls-port", "0.0.0.0:443"]).unwrap_err();
        CommandOpts::<Opts>::try_parse_from(["server", "--monitoring-tls-port", "0.0.0.0:443"])
            .unwrap_err();
        CommandOpts::<Opts>::try_parse_from(["server", "--control-tls-port", "0.0.0.0:443"])
            .unwrap_err();
    }
}
