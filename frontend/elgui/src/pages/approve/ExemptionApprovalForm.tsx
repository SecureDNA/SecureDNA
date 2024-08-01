/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import { AnimatePresence, motion } from "framer-motion";
import { EtrSummary, Page } from "src/components";
import OverviewPage from "./OverviewPage";
import ScreeningPage from "./ScreeningPage";
import SigningPage from "./SigningPage";
import UploadPage from "./UploadPage";
import { PageNumber, useApprovalStore } from "./store";

const ExemptionApprovalForm = () => {
  const etr = useApprovalStore((state) => state.etr);
  const pageIndex = useApprovalStore((state) => state.pageIndex);
  const direction = useApprovalStore((state) => state.direction);

  const variants = {
    enter: (direction: number) => ({
      x: 20 * direction,
      opacity: 0,
    }),
    center: { zIndex: 1, x: 0, opacity: 1 },
    exit: (direction: number) => ({
      zIndex: 0,
      x: -20 * direction,
      opacity: 0,
    }),
  };

  return (
    <Page title="Exemption Approval Tool">
      <div className="w-full max-w-3xl my-4">
        {/* <div className="px-16 pb-8">
          <Progress
            labels={["Choose file", "Overview", "Screening", "Sign"]}
            currentIndex={pageIndex}
          />
        </div> */}
        {etr && pageIndex < 3 && (
          <div className="text-center">
            <EtrSummary etr={etr} />
          </div>
        )}
        <AnimatePresence initial={false} mode="wait" custom={direction}>
          <motion.div
            key={pageIndex}
            custom={direction}
            variants={variants}
            initial="enter"
            animate="center"
            exit="exit"
            transition={{ duration: 0.1 }}
          >
            {pageIndex === PageNumber.Upload ? (
              <UploadPage />
            ) : pageIndex === PageNumber.Overview ? (
              <OverviewPage />
            ) : pageIndex === PageNumber.Screen ? (
              <ScreeningPage />
            ) : (
              <SigningPage />
            )}
          </motion.div>
        </AnimatePresence>
      </div>
    </Page>
  );
};

export default ExemptionApprovalForm;
