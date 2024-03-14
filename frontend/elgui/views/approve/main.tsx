/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import React from "react";
import ReactDOM from "react-dom/client";
import { Toaster } from "react-hot-toast";
import ExemptionApprovalForm from "src/pages/approve/ExemptionApprovalForm";
import "src/style";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <Toaster position="top-left" />
    <ExemptionApprovalForm />
  </React.StrictMode>
);
