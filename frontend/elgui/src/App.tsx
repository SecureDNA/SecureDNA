/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import "@fontsource-variable/dm-sans";
import "@fontsource/dm-sans";
import { Toaster } from "react-hot-toast";
import { HashRouter, NavLink, Route, Routes } from "react-router-dom";
import {
  ExemptionApprovalForm,
  ExemptionRequestForm,
  Inspect,
  ScreeningTest,
  Storybook,
  StorybookPage,
  SubsetForm,
} from "./pages";

function App() {
  const navClass = ({ isActive }: { isActive: boolean }) =>
    isActive ? "font-bold hover:underline" : "hover:underline";

  return (
    <HashRouter>
      <Toaster position="top-left" />
      <div className="App flex flex-col items-center">
        <Routes>
          <Route index element={<ExemptionRequestForm />} />
          <Route path="approve" element={<ExemptionApprovalForm />} />
          <Route path="inspect" element={<Inspect />} />
          <Route path="subset" element={<SubsetForm />} />
          <Route path="screening-test" element={<ScreeningTest />} />
          <Route path="storybook" element={<Storybook />}>
            <Route path=":page" element={<StorybookPage />} />
          </Route>
        </Routes>
        <nav className="bg-primary fixed z-40 left-0 bottom-0 flex space-x-4 py-2 px-4">
          <NavLink className={navClass} to="/">
            Request
          </NavLink>
          <NavLink className={navClass} to="/approve">
            Approve
          </NavLink>
          <NavLink className={navClass} to="/inspect">
            Inspect
          </NavLink>
          <NavLink className={navClass} to="/subset">
            Subset
          </NavLink>
          <NavLink className={navClass} to="/screening-test">
            Screening Test
          </NavLink>
          <NavLink className={navClass} to="/storybook/form">
            Storybook
          </NavLink>
        </nav>
      </div>
    </HashRouter>
  );
}

export default App;
