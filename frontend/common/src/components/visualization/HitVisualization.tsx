/**
 * Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

import type { FastaRecordHits, HazardHits, HitRegion } from "../..";
import { HitRectangle } from "./HitRectangle";

export interface HitVisualizationProps {
  hit: HazardHits;
  region: HitRegion;
  hovered: string;
  group: FastaRecordHits;
  allLikelyOrganisms: string[];
}

/// Given an index in a list of hit organisms, return a hue between 0 and 359.
/// I forget where I picked up this trick, but advancing by the "golden angle"
/// produces a set of maximally distant hues in a specific sense:
///
/// https://math.stackexchange.com/questions/93623/does-the-golden-angle-produce-maximally-distant-divisions-of-a-circle
///
/// The 222.5 here is approximately 360 * phi mod 360.
///
export function organismHue(index: number): number {
  return (index * 222.5) % 360;
}

export const HitVisualization = (props: HitVisualizationProps) => {
  const { hit, region, hovered, group, allLikelyOrganisms } = props;
  const start = Number(region.seq_range_start);
  const end = Number(region.seq_range_end);
  const length = Number(group.sequence_length);
  const startPercent = (start / length) * 100;
  const endPercent = 100 - (end / length) * 100;
  const selected =
    hit.most_likely_organism.ans.includes(hovered) ||
    hit.most_likely_organism.name === hovered;
  const index = allLikelyOrganisms.indexOf(hit.most_likely_organism.name);
  const top = `${(index / allLikelyOrganisms.length) * 100}%`;
  const bottom = `${100 - ((index + 1) / allLikelyOrganisms.length) * 100}%`;
  const hue = organismHue(index);
  const muted = !selected && hovered !== "";
  return (
    <HitRectangle
      startPercent={startPercent}
      endPercent={endPercent}
      selected={selected}
      muted={muted}
      isWildType={hit.is_wild_type ?? false}
      hueDegrees={hue}
      saturationPercentage={60}
      yDisplacementPixels={0}
      top={top}
      bottom={bottom}
    />
  );
};
