/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import "@fontsource-variable/inter";
import "@fontsource/inter";
import { Toaster } from "react-hot-toast";
import { HashRouter, NavLink, Route, Routes } from "react-router-dom";
import {
  ExemptionApprovalForm,
  ExemptionRequestForm,
  InspectElt,
  ScreeningPerf,
} from "./pages";

function App() {
  const navClass = ({ isActive }: { isActive: boolean }) =>
    isActive
      ? "text-primary-light hover:underline"
      : "text-white hover:underline";

  return (
    <HashRouter>
      <Toaster position="top-left" />
      <div className="App flex flex-col items-center">
        <nav className="absolute w-full flex justify-end space-x-4 py-2 px-4">
          <NavLink className={navClass} to="/">
            Request form
          </NavLink>
          <NavLink className={navClass} to="/approve">
            Approval form
          </NavLink>
          <NavLink className={navClass} to="/inspect-elt">
            Inspect ELT
          </NavLink>
          {/* <NavLink className={navClass} to="/screening-perf">
            Screening perf
          </NavLink> */}
        </nav>
        <Routes>
          <Route path="/" element={<ExemptionRequestForm />} />
          <Route path="/approve" element={<ExemptionApprovalForm />} />
          <Route path="/inspect-elt" element={<InspectElt />} />
          <Route path="/screening-perf" element={<ScreeningPerf />} />
        </Routes>
      </div>
    </HashRouter>
  );
}

export default App;
