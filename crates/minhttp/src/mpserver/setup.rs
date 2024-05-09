// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::common::disabled_service;
use super::traits::{
    AppConfig, AppState, ConnectedFn, ConnectionFailedFn, DisconnectedFn, ReconfigureFn,
    ResponseFn, ValidExternalWorld, ValidServerSetup,
};
use super::{MultiplaneServer, ServerConfig};

/// Aspects of a [`MultiplaneServer`] that can't be changed at runtime
///
/// Holds everything (responders, etc) that makes something a particular kind of server.
/// Unlike [`ExternalWorld`](super::ExternalWorld), [`ServerSetup`] only has things that don't
/// depend on e.g. whether the external world is a test.
#[derive(Clone)]
pub struct ServerSetup<
    Reconfigure,
    Respond,
    RespondToMonitoring,
    RespondToControl,
    Connected,
    ConnectionFailed,
    Disconnected,
> {
    /// Server reconfiguration callback; must be a [`ReconfigureFn`].
    pub reconfigure: Reconfigure,
    /// Main HTTP response callback; must be a [`ResponseFn`] compatible with [`self.reconfigure`](Self::reconfigure).
    pub respond: Respond,
    /// Monitoring HTTP response callback; must be a [`ResponseFn`] compatible with [`self.reconfigure`](Self::reconfigure).
    pub respond_to_monitoring: RespondToMonitoring,
    /// Control HTTP response callback; must be a [`ResponseFn`] compatible with [`self.reconfigure`](Self::reconfigure).
    pub respond_to_control: RespondToControl,
    /// New connection state/monitoring callback; must be a [`ConnectedFn`].
    pub connected: Connected,
    /// Connection failure callback; must be a [`ConnectionFailedFn`].
    pub connection_failed: ConnectionFailed,
    /// Terminated connection callback; must be a [`DisconnectedFn`] compatible with [`self.connected`](Self::connected).
    pub disconnected: Disconnected,
}

/// Indicates you forgot to specify `respond` in [`ServerSetup`]
pub struct MissingCallback;

impl ServerSetup<(), (), (), (), (), (), ()> {
    /// Constructs an unconfigured [`ServerSetup`]
    ///
    /// The returned [`ServerSetup`] will have some sensible defaults, but will need to have
    /// [`with_reconfigure`](Self::with_reconfigure) and [`with_response`](Self::with_response)
    /// called on it because it becomes valid.
    pub fn new() -> ServerSetup<
        MissingCallback,
        MissingCallback,
        MissingCallback,
        MissingCallback,
        impl ConnectedFn<ConnectionState = ()>,
        impl ConnectionFailedFn,
        impl DisconnectedFn<()>,
    > {
        ServerSetup {
            reconfigure: MissingCallback,
            respond: MissingCallback,
            respond_to_monitoring: MissingCallback,
            respond_to_control: MissingCallback,
            connected: |_| {},
            connection_failed: |_| {},
            disconnected: |_| {},
        }
    }
}

impl<
        Reconfigure,
        Respond,
        RespondToMonitoring,
        RespondToControl,
        Connected,
        ConnectionFailed,
        Disconnected,
    >
    ServerSetup<
        Reconfigure,
        Respond,
        RespondToMonitoring,
        RespondToControl,
        Connected,
        ConnectionFailed,
        Disconnected,
    >
{
    /// Sets server reconfiguration callback.
    ///
    /// Whenever [`MultiplaneServer::reload_cfg`] is called, this callback will be given an app
    /// config `AC`, and the previous application state `AS`, and must attempt to construct a
    /// new application state to be used by the serve from now on.
    ///
    /// Note that calling this wipes out [`self.respond`](Self::respond), and populates
    /// [`self.respond_to_monitoring`](Self::respond_to_monitoring)
    /// and [`self.respond_to_control`](Self::respond_to_control) with stubs.
    pub fn with_reconfigure<AC, AS: AppState, R: ReconfigureFn<AC, AS>>(
        self,
        reconfigure: R,
    ) -> ServerSetup<
        R,
        MissingCallback,
        impl ResponseFn<AS>,
        impl ResponseFn<AS>,
        Connected,
        ConnectionFailed,
        Disconnected,
    > {
        ServerSetup {
            reconfigure,
            respond: MissingCallback,
            respond_to_monitoring: disabled_service,
            respond_to_control: disabled_service,
            connected: self.connected,
            connection_failed: self.connection_failed,
            disconnected: self.disconnected,
        }
    }

    /// Sets main HTTP response callback.
    ///
    /// Whenever the server receives an HTTP request, this is invoked to generate a response.
    /// It's also passed the app state of type `AS` and connection address.
    pub fn with_response<AC, AS, R>(
        self,
        respond: R,
    ) -> ServerSetup<
        Reconfigure,
        R,
        RespondToMonitoring,
        RespondToControl,
        Connected,
        ConnectionFailed,
        Disconnected,
    >
    where
        Reconfigure: ReconfigureFn<AC, AS>,
        R: ResponseFn<AS>,
    {
        ServerSetup {
            reconfigure: self.reconfigure,
            respond,
            respond_to_monitoring: self.respond_to_monitoring,
            respond_to_control: self.respond_to_control,
            connected: self.connected,
            connection_failed: self.connection_failed,
            disconnected: self.disconnected,
        }
    }

    /// Sets monitoring HTTP response callback.
    ///
    /// Whenever the server receives an HTTP request on the monitoring plane, this is invoked to
    /// generate a response. It's also passed the app state of type `AS` and connection address.
    pub fn with_response_to_monitoring<AC, AS, R>(
        self,
        respond_to_monitoring: R,
    ) -> ServerSetup<
        Reconfigure,
        Respond,
        R,
        RespondToControl,
        Connected,
        ConnectionFailed,
        Disconnected,
    >
    where
        Reconfigure: ReconfigureFn<AC, AS>,
        R: ResponseFn<AS>,
    {
        ServerSetup {
            reconfigure: self.reconfigure,
            respond: self.respond,
            respond_to_monitoring,
            respond_to_control: self.respond_to_control,
            connected: self.connected,
            connection_failed: self.connection_failed,
            disconnected: self.disconnected,
        }
    }

    /// Sets control HTTP response callback.
    ///
    /// Whenever the server receives an HTTP request on the control plane, this is invoked to
    /// generate a response. It's also passed the app state of type `AS` and connection address.
    pub fn with_response_to_control<AC, AS, R>(
        self,
        respond_to_control: R,
    ) -> ServerSetup<
        Reconfigure,
        Respond,
        RespondToMonitoring,
        R,
        Connected,
        ConnectionFailed,
        Disconnected,
    >
    where
        Reconfigure: ReconfigureFn<AC, AS>,
        R: ResponseFn<AS>,
    {
        ServerSetup {
            reconfigure: self.reconfigure,
            respond: self.respond,
            respond_to_monitoring: self.respond_to_monitoring,
            respond_to_control,
            connected: self.connected,
            connection_failed: self.connection_failed,
            disconnected: self.disconnected,
        }
    }

    /// New connection callback used for monitoring purposes.
    ///
    /// Note that calling this wipes out [`self.disconnected`](Self::disconnected).
    pub fn with_connected<C>(
        self,
        connected: C,
    ) -> ServerSetup<
        Reconfigure,
        Respond,
        RespondToMonitoring,
        RespondToControl,
        C,
        ConnectionFailed,
        impl DisconnectedFn<C::ConnectionState>,
    >
    where
        C: ConnectedFn,
    {
        ServerSetup {
            reconfigure: self.reconfigure,
            respond: self.respond,
            respond_to_monitoring: self.respond_to_monitoring,
            respond_to_control: self.respond_to_control,
            connected,
            connection_failed: self.connection_failed,
            disconnected: |_| {},
        }
    }

    /// Connection failure callback used for monitoring purposes.
    pub fn with_connection_failed<C>(
        self,
        connection_failed: C,
    ) -> ServerSetup<
        Reconfigure,
        Respond,
        RespondToMonitoring,
        RespondToControl,
        Connected,
        C,
        Disconnected,
    >
    where
        C: ConnectionFailedFn,
    {
        ServerSetup {
            reconfigure: self.reconfigure,
            respond: self.respond,
            respond_to_monitoring: self.respond_to_monitoring,
            respond_to_control: self.respond_to_control,
            connected: self.connected,
            connection_failed,
            disconnected: self.disconnected,
        }
    }

    /// Disconnection callback used for monitoring purposes.
    pub fn with_disconnected<D>(
        self,
        disconnected: D,
    ) -> ServerSetup<
        Reconfigure,
        Respond,
        RespondToMonitoring,
        RespondToControl,
        Connected,
        ConnectionFailed,
        D,
    >
    where
        Connected: ConnectedFn,
        D: DisconnectedFn<Connected::ConnectionState>,
    {
        ServerSetup {
            reconfigure: self.reconfigure,
            respond: self.respond,
            respond_to_monitoring: self.respond_to_monitoring,
            respond_to_control: self.respond_to_control,
            connected: self.connected,
            connection_failed: self.connection_failed,
            disconnected,
        }
    }

    /// Builds a new [`MultiplaneServer`] attached to an [`ExternalWorld`](super::ExternalWorld).
    pub fn build_with_external_world<AC, AS, ExternalWorld>(
        self,
        external_world: ExternalWorld,
    ) -> MultiplaneServer
    where
        AC: AppConfig,
        AS: AppState,
        Self: ValidServerSetup<AC, AS>,
        ExternalWorld: ValidExternalWorld<ServerConfig<AC>>,
    {
        MultiplaneServer::new(self, external_world.to_external_world())
    }
}
