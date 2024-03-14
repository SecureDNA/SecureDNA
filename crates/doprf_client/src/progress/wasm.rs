// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use shared_types::requests::RequestContext;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Progress {
    pub done: bool,
    pub id: String,
    pub progress: f64,
}

/// How many calls to report_progress() are made per screening? This is used to
/// calculate progress increments: if there are 5 calls per screening, and the request
/// consists of 2 FASTA records, then increment by 1/10 each time.
const PROGRESS_REPORTS_PER_SCREENING: usize = 5;

pub fn report_progress(request_ctx: &RequestContext) {
    if let Ok(ports) = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("$ports")) {
        let id = JsValue::from_str(&request_ctx.id.0);
        if let Ok(port) = js_sys::Reflect::get(&ports, &id) {
            if let Ok(port) = port.dyn_into::<web_sys::MessagePort>() {
                let object = Progress {
                    done: false,
                    id: request_ctx.id.0.clone(),
                    progress: 1.0
                        / (request_ctx.total_records * PROGRESS_REPORTS_PER_SCREENING) as f64,
                };
                if let Err(e) = port.post_message(&serde_wasm_bindgen::to_value(&object).unwrap()) {
                    web_sys::console::error_2(&JsValue::from_str("postMessage error"), &e);
                }
            } else {
                web_sys::console::error_3(&JsValue::from_str("Not a MessagePort at"), &ports, &id);
            }
        } else {
            web_sys::console::error_3(&JsValue::from_str("Ports doesn't have key"), &ports, &id);
        }
    } else {
        web_sys::console::error_2(
            &JsValue::from_str("Couldn't get ports on global"),
            &js_sys::global(),
        );
    }
}
