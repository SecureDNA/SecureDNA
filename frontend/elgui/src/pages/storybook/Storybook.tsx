/**
 * Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { Page } from "@securedna/frontend_common";
import { NavLink, Outlet } from "react-router-dom";

export default function Storybook() {
  const navClass = ({ isActive }: { isActive: boolean }) =>
    isActive ? "font-bold hover:underline" : "hover:underline";

  return (
    <Page title="Storybook">
      <div className="flex flex-row max-w-4xl w-full items-stretch">
        <div className="flex flex-col border-r p-4 min-w-40">
          <NavLink className={navClass} to="/storybook/typography">
            Typography
          </NavLink>
          <NavLink className={navClass} to="/storybook/form">
            Form
          </NavLink>
          <NavLink className={navClass} to="/storybook/card">
            Card
          </NavLink>
          <NavLink className={navClass} to="/storybook/screening">
            Screening
          </NavLink>
          <NavLink className={navClass} to="/storybook/auth-feedback">
            Auth feedback
          </NavLink>
        </div>
        <div className="flex flex-col px-8 py-4 w-full mb-12">
          <Outlet />
        </div>
      </div>
    </Page>
  );
}
