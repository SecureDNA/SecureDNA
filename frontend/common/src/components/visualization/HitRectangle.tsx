/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import React from "react";

export interface HitRectangleProps {
  startPercent: number;
  endPercent: number;
  selected: boolean;
  muted: boolean;
  isWildType: boolean;
  hueDegrees: number;
  saturationPercentage: number;
  yDisplacementPixels: number;
  top: string | number;
  bottom: string | number;
}

export const HitRectangle = (props: HitRectangleProps) => {
  const hue = props.hueDegrees;
  const saturation = props.saturationPercentage;
  const outline = props.isWildType ? "solid" : "dashed";
  const background = props.muted
    ? "#88888840"
    : `hsla(${hue}, ${saturation}%, 60%, 0.8)`;
  const border = props.selected
    ? `2px ${outline} hsla(${hue}, ${saturation}%, 40%, 1)`
    : "none";
  const zIndex = props.muted ? 0 : 5;

  return (
    <div
      className="absolute"
      style={{
        left: `${props.startPercent}%`,
        right: `${props.endPercent}%`,
        transition: "transform 0.1s",
        transform: `translateY(${props.yDisplacementPixels}px)`,
        top: props.top,
        bottom: props.bottom,
        background,
        border,
        borderRadius: "2px",
        zIndex,
        minWidth: "8px",
      }}
    ></div>
  );
};

export const ExampleHitRectangle = (props: { isWildType: boolean }) => (
  <HitRectangle
    startPercent={0}
    endPercent={0}
    selected={true}
    muted={false}
    isWildType={props.isWildType}
    hueDegrees={0}
    saturationPercentage={0}
    yDisplacementPixels={0}
    top={0}
    bottom={0}
  />
);
