// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Common API for streaming HTTP requests and responses.

use http::{Request, Response};
use hyper::body::Body;
use hyper::service::Service;

mod dyns;
mod outsourced;
pub mod portable;
pub mod reqwest;
pub mod util;

/// Common API for asynchronously serving HTTP with streamed [`Request`]/[`Response`] bodies.
///
/// This is _very_ similar to [`hyper::service::HttpService`] except that errors aren't
/// required to be boxable and type inference between [`HttpService`] and equivalent
/// [`hyper::service::Service`] implementations is bidirectional. The way to implement
/// [`HttpService`] is implementing an equivalent [`hyper::service::Service`], either
/// manually or with something like [`hyper::service::service_fn`] or [`util::ServiceFn`].
///
/// [`tower::Service`] is another similar trait that's tempting to use due to the large ecosystem
/// around it but my attempts to use it hit some snags:
/// * Our existing codebase expects to be able to use services concurently, whereas the
///   [`tower::Service`] trait expects to be called serially. This isn't insurmountable;
///   see [`TowerToHyperService`] for an example solution.
/// * My attempts with [`tower::Service`] were dramatically more verbose, as layers can't
///   use [`tower::service_fn`] because it won't correctly delegate [`poll_ready`].
///
/// Ultimately, if we later decide to use the [`tower`] ecosystem, there *are* existing
/// adapters (such as the aforementioned [`TowerToHyperService`]) that'll be compatible with this.
///
///  [`tower`]: https://docs.rs/tower/latest/tower/
///  [`tower::Service`]: https://docs.rs/tower/latest/tower/trait.Service.html
///  [`TowerToHyperService`]: https://docs.rs/hyper-util/latest/hyper_util/service/struct.TowerToHyperService.html
///  [`tower::service_fn`]: https://docs.rs/tower/latest/tower/fn.service_fn.html
///  [`poll_ready`]: https://docs.rs/tower/latest/tower/trait.Service.html#tymethod.poll_ready
pub trait HttpService<RequestBody>:
    Service<Request<RequestBody>, Response = Response<Self::ResponseBody>>
{
    type ResponseBody: Body;

    fn send(&self, request: Request<RequestBody>) -> Self::Future;
}

impl<T, RequestBody, ResBody> HttpService<RequestBody> for T
where
    T: ?Sized + Service<Request<RequestBody>, Response = Response<ResBody>>,
    ResBody: Body,
{
    type ResponseBody = ResBody;

    fn send(&self, request: Request<RequestBody>) -> Self::Future {
        self.call(request)
    }
}
