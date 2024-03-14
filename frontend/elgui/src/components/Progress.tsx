/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

interface ProgressProps {
  labels: string[];
  currentIndex: number;
}

interface ProgressStepProps {
  index: number;
  state: "future" | "current" | "done";
  label: string;
}

const ProgressStep = (props: ProgressStepProps) => {
  let ballClasses =
    "flex items-center justify-center text-lg w-8 h-8 rounded-full";
  ballClasses +=
    props.state === "future" ? " bg-black/10" : " bg-primary text-white";
  let labelClasses =
    "w-8 text-center flex items-center justify-center whitespace-nowrap";
  if (props.state === "current") labelClasses += " font-bold text-primary";
  return (
    <div className="flex flex-col items-center">
      <div className={ballClasses}>{props.index + 1}</div>
      <div className={labelClasses}>{props.label}</div>
    </div>
  );
};

export const Progress = (props: ProgressProps) => {
  let children = [];
  for (let i = 0; i < props.labels.length; i++) {
    if (i > 0) {
      let stickClasses = "flex-1 h-1 mt-[0.875rem]";
      stickClasses += i > props.currentIndex ? " bg-black/10" : " bg-primary";
      children.push(<div key={i - 0.5} className={stickClasses}></div>);
    }
    children.push(
      <ProgressStep
        key={i}
        index={i}
        state={
          i > props.currentIndex
            ? "future"
            : i === props.currentIndex
              ? "current"
              : "done"
        }
        label={props.labels[i]}
      />
    );
  }
  return <div className="flex items-top select-none">{children}</div>;
};
