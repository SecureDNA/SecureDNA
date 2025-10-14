// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

/// Indexes marking the beginning and end of the hit region, as well as the index of the last
/// window in the range.
///
/// An example (with arbitrary window size 20)
///
/// ```text
/// seq_range_start                              seq_range_end
/// ▼                        ▼                   ▼
/// AAAAAAAAAAAAAAAAAAAATTTTTCCCCCCCCCCCCCCCCCCCC
/// ────────────────────
///      one window
///
/// seq_range_start = 0
/// seq_range_end = 45
/// window_starts = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]
/// window_count = 2
/// ```
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct HitRegion {
    /// Index (in the original sequence) of the start of the hit region
    pub seq_range_start: usize,
    /// Index (in the original sequence) of the end of the hit region range. This range bound is
    /// exclusive.
    pub seq_range_end: usize,
    /// Index (in the original sequence) of the start of each window in the hit region
    pub window_starts: Vec<usize>,
    /// Debug usage only, not intended for API output. The number of windows within the hit region.
    pub window_count: usize,
    /// Debug usage only, not intended for API output. The [`HashTypeDescriptor`] of the windows.
    ///
    /// [`HashTypeDescriptor`]: shared_types::hash::HashTypeDescriptor
    pub htd_index: usize,
}

impl HitRegion {
    /// Returns the regions that remain after subtracting the other region.
    /// the removed region will be added to `removed_regions` if a vec is provided.
    pub fn subtract(
        self,
        other: &HitRegion,
        removed_regions: &mut Option<Vec<HitRegion>>,
    ) -> [Option<HitRegion>; 2] {
        let start = self.seq_range_start.max(other.seq_range_start);
        let end = self.seq_range_end.min(other.seq_range_end);

        if start >= end {
            // No overlap
            return [Some(self), None];
        }

        let mut remaining = [None, None];
        let mut count = 0;

        if start > self.seq_range_start {
            remaining[0] = Some(self.extract_region(self.seq_range_start, start));
            count += 1;
        }
        if end < self.seq_range_end {
            remaining[count as usize] = Some(self.extract_region(end, self.seq_range_end));
        }

        if let Some(removed_regions) = removed_regions {
            removed_regions.push(self.extract_region(start, end));
        }

        remaining
    }

    pub fn overlaps(&self, start: usize, end: usize) -> bool {
        self.seq_range_start < end && self.seq_range_end > start
    }

    /// Creates a new hit region from a section of the original region
    fn extract_region(&self, start: usize, end: usize) -> HitRegion {
        let window_starts = self.window_starts_in_range(start, end);
        let window_count = window_starts.len();
        HitRegion {
            seq_range_start: start,
            seq_range_end: end,
            window_starts,
            window_count,
            htd_index: self.htd_index,
        }
    }

    /// Returns the start indices of windows within the given range.
    /// `range_end` is exclusive.
    fn window_starts_in_range(&self, range_start: usize, range_end: usize) -> Vec<usize> {
        let start_idx = match self.window_starts.iter().position(|&s| s >= range_start) {
            // Includes start of previous window if the first window starts after the range start
            Some(idx) if range_start < self.window_starts[idx] && idx > 0 => idx - 1,
            Some(idx) => idx,
            None if !self.window_starts.is_empty() => self.window_starts.len() - 1,
            None => return Vec::new(),
        };

        // Take windows starting before range_end
        self.window_starts[start_idx..]
            .iter()
            .take_while(|&&start| start < range_end)
            .copied()
            .collect()
    }
}

/// Subtracts one list of hit regions from another.
/// If a vec is supplied for 'removed_regions', it will be populated with the removed regions.
/// As each region is removed, up to two remainder regions may be created.
/// The regions to be removed are iterated over in the outer loop, allowing each subsequent region
/// to be subtracted from only the regions remaining from the previous subtractions.
pub fn remove_multiple_regions<'a>(
    regions: Vec<HitRegion>,
    to_remove: impl Iterator<Item = &'a HitRegion>,
    removed_regions: &mut Option<Vec<HitRegion>>,
) -> Vec<HitRegion> {
    to_remove.fold(regions, |remaining, to_remove| {
        if remaining.is_empty() {
            return remaining;
        }
        let mut next_remaining = Vec::with_capacity(2 * remaining.len());
        for region in remaining {
            let retained = region.subtract(to_remove, removed_regions);
            next_remaining.extend(retained.into_iter().flatten());
        }
        next_remaining
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtract_no_overlap() {
        let region = HitRegion {
            seq_range_start: 10,
            seq_range_end: 20,
            window_starts: vec![10, 15],
            window_count: 2,
            htd_index: 3,
        };

        let mut removed = Some(vec![]);
        let remaining = remove_multiple_regions(
            vec![region],
            [
                HitRegion {
                    seq_range_start: 30,
                    seq_range_end: 40,
                    window_starts: vec![30, 35],
                    window_count: 2,
                    htd_index: 3,
                },
                HitRegion {
                    seq_range_start: 50,
                    seq_range_end: 60,
                    window_starts: vec![50, 55],
                    window_count: 2,
                    htd_index: 3,
                },
            ]
            .iter(),
            &mut removed,
        );

        assert_eq!(
            remaining,
            vec![HitRegion {
                seq_range_start: 10,
                seq_range_end: 20,
                window_starts: vec![10, 15],
                window_count: 2,
                htd_index: 3,
            }]
        );
        assert_eq!(removed, Some(vec![]));
    }

    #[test]
    fn subtract_multiple_overlapping_regions() {
        let region = HitRegion {
            seq_range_start: 10,
            seq_range_end: 50,
            window_starts: vec![10, 15, 35],
            window_count: 3,
            htd_index: 3,
        };

        let mut removed = Some(vec![]);
        let remaining = remove_multiple_regions(
            vec![region],
            [
                HitRegion {
                    seq_range_start: 15,
                    seq_range_end: 25,
                    window_starts: vec![15],
                    window_count: 1,
                    htd_index: 3,
                },
                HitRegion {
                    seq_range_start: 35,
                    seq_range_end: 45,
                    window_starts: vec![35],
                    window_count: 1,
                    htd_index: 3,
                },
            ]
            .iter(),
            &mut removed,
        );

        assert_eq!(
            remaining,
            vec![
                HitRegion {
                    seq_range_start: 10,
                    seq_range_end: 15,
                    window_starts: vec![10],
                    window_count: 1,
                    htd_index: 3,
                },
                HitRegion {
                    seq_range_start: 25,
                    seq_range_end: 35,
                    window_starts: vec![15],
                    window_count: 1,
                    htd_index: 3,
                },
                HitRegion {
                    seq_range_start: 45,
                    seq_range_end: 50,
                    window_starts: vec![35],
                    window_count: 1,
                    htd_index: 3,
                }
            ]
        );

        assert_eq!(
            removed,
            Some(vec![
                HitRegion {
                    seq_range_start: 15,
                    seq_range_end: 25,
                    window_starts: vec![15],
                    window_count: 1,
                    htd_index: 3,
                },
                HitRegion {
                    seq_range_start: 35,
                    seq_range_end: 45,
                    window_starts: vec![35],
                    window_count: 1,
                    htd_index: 3,
                }
            ])
        );
    }

    #[test]
    fn subtract_overlapping_regions_where_first_remainder_overlaps() {
        let region = HitRegion {
            seq_range_start: 10,
            seq_range_end: 50,
            window_starts: vec![10, 15],
            window_count: 2,
            htd_index: 3,
        };

        let mut removed = Some(vec![]);
        let remaining = remove_multiple_regions(
            vec![region],
            [
                HitRegion {
                    seq_range_start: 15,
                    seq_range_end: 25,
                    window_starts: vec![15],
                    window_count: 1,
                    htd_index: 3,
                },
                HitRegion {
                    seq_range_start: 10,
                    seq_range_end: 15,
                    window_starts: vec![10],
                    window_count: 1,
                    htd_index: 3,
                },
            ]
            .iter(),
            &mut removed,
        );

        assert_eq!(
            remaining,
            vec![HitRegion {
                seq_range_start: 25,
                seq_range_end: 50,
                window_starts: vec![15],
                window_count: 1,
                htd_index: 3,
            }]
        );
        assert_eq!(
            removed,
            Some(vec![
                HitRegion {
                    seq_range_start: 15,
                    seq_range_end: 25,
                    window_starts: vec![15],
                    window_count: 1,
                    htd_index: 3,
                },
                HitRegion {
                    seq_range_start: 10,
                    seq_range_end: 15,
                    window_starts: vec![10],
                    window_count: 1,
                    htd_index: 3,
                }
            ])
        );
    }

    #[test]
    fn subtract_overlapping_regions_complete_overlap() {
        let region = HitRegion {
            seq_range_start: 10,
            seq_range_end: 20,
            window_starts: vec![12, 15],
            window_count: 2,
            htd_index: 3,
        };

        let mut removed = Some(vec![]);
        let remaining = remove_multiple_regions(
            vec![region],
            [HitRegion {
                seq_range_start: 5,
                seq_range_end: 25,
                window_starts: vec![5, 10],
                window_count: 2,
                htd_index: 3,
            }]
            .iter(),
            &mut removed,
        );

        assert_eq!(remaining, vec![]);
        assert_eq!(
            removed,
            Some(vec![HitRegion {
                seq_range_start: 10,
                seq_range_end: 20,
                window_starts: vec![12, 15],
                window_count: 2,
                htd_index: 3,
            }])
        );
    }

    #[test]
    fn subtract_overlapping_regions_empty_other_regions() {
        let region = HitRegion {
            seq_range_start: 10,
            seq_range_end: 20,
            window_starts: vec![12, 15],
            window_count: 2,
            htd_index: 3,
        };

        let mut removed = Some(vec![]);
        let remaining = remove_multiple_regions(vec![region], [].iter(), &mut removed);

        assert_eq!(
            remaining,
            vec![HitRegion {
                seq_range_start: 10,
                seq_range_end: 20,
                window_starts: vec![12, 15],
                window_count: 2,
                htd_index: 3,
            }]
        );
        assert_eq!(removed, Some(vec![]));
    }
}
