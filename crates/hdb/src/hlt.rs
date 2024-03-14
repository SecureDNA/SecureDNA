// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This module implements the Hazard Lookup Table, which metadata entries will
//! reference for sets of accession numbers.

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io,
    path::{Path, PathBuf},
};

use rand::Rng;
use serde::{Deserialize, Serialize};

use pipeline_bridge::{OrganismType, Tag};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash, Serialize, Deserialize)]
pub enum HLTId {
    OrganismName(String),
    Accession(String),
    // Free-form tags per organism, intended for client-side users to enable custom logic.
    // Also includes some private SDNA tags which are filtered before constructing the hdb
    // response.
    Tag(Tag),
    // Tiled if tag is present, shingled if not
    Tiled,
    OrganismType(OrganismType),
}

impl HLTId {
    pub fn organism_name(&self) -> Option<&str> {
        match self {
            Self::OrganismName(s) => Some(s),
            _ => None,
        }
    }

    pub fn accession(&self) -> Option<&str> {
        match self {
            Self::Accession(s) => Some(s),
            _ => None,
        }
    }

    pub fn tag(&self) -> Option<&Tag> {
        match self {
            Self::Tag(s) => Some(s),
            _ => None,
        }
    }

    pub fn tiled(&self) -> bool {
        matches!(self, Self::Tiled)
    }

    pub fn organism_type(&self) -> Option<OrganismType> {
        match self {
            Self::OrganismType(s) => Some(*s),
            _ => None,
        }
    }
}

type IdGroupsVec = Vec<Vec<HLTId>>;

/// Hazard lookup table, which maps from u32 index to HLTEntry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HazardLookupTable {
    /// Mapping from HLT index -> Entry. We use a HashMap instead of a Vec even
    /// though the indexes are numeric underlying-ly because indexes aren't contiguous,
    /// we assign them randomly so insertion order can't be determined if someone steals
    /// a database without the associated HLT (See [[Database storage and lookup]])
    entries: HashMap<u32, HLTEntry>,
    /// Cache for merging entries, so if the merge would result in something that already
    /// is in the table, we return that existing ID instead.
    /// This is only populated with merge results, so we're not maintaining a massive bidirectional
    /// map.
    /// It's also not serialized, so a deserialized HLT may generate duplicates if merging
    /// is performed on the deserialized HLT. This isn't our current (Aug 2022) usage pattern, however.
    #[serde(default, skip)]
    merge_cache: HashMap<IdGroupsVec, u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
pub struct HLTEntry {
    /// List of identifiers in this entry. The nested vec is so that identifiers can be grouped,
    /// for equivalence, or for grouping an organism's accessions together if hazards are only
    /// associated with an organism and not a specific accession.
    id_groups: IdGroupsVec,
}

impl HLTEntry {
    /// Constructs a new HLTEntry from a list of ID groups. Panics if the number of groups is greater
    /// than 256, since then some groups can't be indexed by a u8.
    pub fn new(id_groups: IdGroupsVec) -> Self {
        assert!(
            id_groups.len() <= 256,
            "too many entries (> 256) in HLTEntry!"
        );
        Self { id_groups }
    }

    /// Number of ID groups in this entry
    pub fn len(&self) -> usize {
        self.id_groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Index of an ID group in this entry
    pub fn index_of(&self, item: &[HLTId]) -> Option<u8> {
        self.iter().find(|(_, o)| item == *o).map(|(idx, _)| idx)
    }

    /// Get an ID group by a u8 index
    pub fn get(&self, an_subindex: u8) -> Option<&[HLTId]> {
        self.id_groups.get(an_subindex as usize).map(|v| &v[..])
    }

    /// Merge an iterator of `HLTEntry`s into a new HLTEntry
    /// Order is not guaranteed.
    fn merge<'a>(entries: impl Iterator<Item = &'a HLTEntry>) -> Self {
        let mut ids = HashSet::new();
        for entry in entries {
            ids.extend(entry.id_groups.iter().cloned());
        }
        let mut vec: IdGroupsVec = ids.into_iter().collect();
        // sort for better hit rate on HLT merge cache
        vec.sort();
        Self::new(vec)
    }

    /// Iter over the (index, ID group)s of this entry
    pub fn iter(&self) -> impl Iterator<Item = (u8, &[HLTId])> {
        self.id_groups.iter().enumerate().map(|(idx, group)| {
            let idx: u8 = idx
                .try_into()
                .expect("too many entries (> 256) in HLTEntry!");
            (idx, &group[..])
        })
    }
}

impl<'a> FromIterator<&'a HLTEntry> for HLTEntry {
    fn from_iter<T: IntoIterator<Item = &'a HLTEntry>>(iter: T) -> Self {
        Self::merge(iter.into_iter())
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum HLTMergeError {
    #[error("Input cannot be an empty slice")]
    EmptyInput,
    #[error("One of the provided indices was invalid")]
    InvalidIndex,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum HLTLookupError {
    #[error("hlt index {0} missing")]
    MissingHLTIndex(u32),
    #[error("an subindex {1} missing for hlt index {0}")]
    MissingANSubindex(u32, u8),
    #[error("hlt[{0}][{1}] has no organism name")]
    MissingOrganismName(u32, u8),
    #[error("hlt[{0}][{1}] has no organism type")]
    MissingOrganismType(u32, u8),
}

impl HazardLookupTable {
    /// Path of the HLT file (hlt.json) within a database directory
    fn self_path(database_path: &Path) -> PathBuf {
        database_path.join("hlt.json")
    }

    fn self_path_compressed(database_path: &Path) -> PathBuf {
        let mut self_path = Self::self_path(database_path);
        self_path.set_extension("json.gz");
        self_path
    }

    /// Read the HLT from a database directory
    pub fn read(database_path: impl AsRef<Path>) -> io::Result<Self> {
        let database_path = database_path.as_ref();

        let compressed_path = Self::self_path_compressed(database_path);
        if compressed_path.exists() {
            let file = File::open(&compressed_path)?;
            Ok(serde_json::from_reader(flate2::bufread::GzDecoder::new(
                io::BufReader::new(file),
            ))?)
        } else {
            let file = File::open(Self::self_path(database_path))?;
            Ok(serde_json::from_reader(io::BufReader::new(file))?)
        }
    }

    /// Write the HLT into a database directory, potentially overwriting an existing one
    pub fn write(&self, database_path: impl AsRef<Path>) -> io::Result<()> {
        let path = Self::self_path(database_path.as_ref());
        let file = File::create(path)?;
        serde_json::to_writer(io::BufWriter::new(file), &self)?;
        Ok(())
    }

    /// Finds a random unoccupied index.
    fn new_index(&self) -> u32 {
        loop {
            let probe = rand::thread_rng().gen();
            if !self.entries.contains_key(&probe) {
                return probe;
            }
        }
    }

    pub fn get(&self, index: &u32) -> Option<&HLTEntry> {
        self.entries.get(index)
    }

    /// Lookup both an hlt_index and the subindex within that group, returning an
    /// error if either is missing.
    pub fn get_with_subindex(
        &self,
        hlt_index: &u32,
        an_subindex: &u8,
    ) -> Result<(&HLTEntry, &[HLTId]), HLTLookupError> {
        let entry = self
            .get(hlt_index)
            .ok_or(HLTLookupError::MissingHLTIndex(*hlt_index))?;
        let group = entry
            .get(*an_subindex)
            .ok_or(HLTLookupError::MissingANSubindex(*hlt_index, *an_subindex))?;
        Ok((entry, group))
    }

    /// Inserts a new entry, returning the chosen index
    pub fn insert(&mut self, entry: HLTEntry) -> u32 {
        let index = self.new_index();
        let should_be_empty = self.entries.insert(index, entry);
        debug_assert!(should_be_empty.is_none());
        index
    }

    /// Merges a set of entries, returning the index of the merged entry.
    /// Panics if an empty slice is passed. Will de-duplicate passed indexes,
    /// and if there's only one unique index, that index will be returned without
    /// mutating self.
    ///
    /// Note that merging could lead to "dead" entries with no references in the DB,
    /// e.g.:
    ///
    /// ```text
    ///     HLT:              { 12: ["α"], 3: ["β"] }
    ///     DB HLT pointers:  [ HashA: 12, HashB: 3, HashA: 3 ]
    /// ```
    ///
    /// if the two HashA entries are merged, the result will be similar to
    ///
    /// ```text
    ///     HLT:              {  12: ["α"], 3: ["β"], 97: ["α", "β"] }
    ///     DB HLT pointers:  [ HashA: 97, HashB: 3 ]
    /// ```
    ///
    /// which will make HLT entry 12 "dead". Since we never delete entries we can't
    /// garbage-collect these, but we assume that they're relatively rare.
    pub fn merge(&mut self, indexes: &[u32]) -> Result<u32, HLTMergeError> {
        let indexes_uniq: HashSet<u32> = indexes.iter().copied().collect();
        match indexes_uniq.len() {
            0 => Err(HLTMergeError::EmptyInput),
            1 => Ok(indexes_uniq.into_iter().next().unwrap()), // no merge needed,
            _ => {
                let merged = indexes_uniq
                    .into_iter()
                    .map(|i| self.get(&i).ok_or(HLTMergeError::InvalidIndex))
                    .collect::<Result<HLTEntry, _>>()?;

                if let Some(&index) = self.merge_cache.get(&merged.id_groups) {
                    Ok(index)
                } else {
                    let id_groups = merged.id_groups.clone();
                    let index = self.insert(merged);
                    self.merge_cache.insert(id_groups, index);
                    Ok(index)
                }
            }
        }
    }

    /// Number of entries in this HLT
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        self.entries.keys().copied()
    }

    /// For every id_group containing HltId { OrganismName: organism_name }, replace all tags in
    /// id_group with the given tags.
    ///
    /// Note: internal tags (prefixed "sdna") will also be updated. However, a change in internal
    /// tags may require a rerun of the pipeline. Generated tags are handled dynamically right before
    /// hdb response.
    ///
    /// TODO: perhaps generate a warning if internal tags are being updated (added or removed)
    pub fn set_tags(&mut self, organism_name: &str, tags: impl IntoIterator<Item = Tag>) {
        let new_tags: Vec<_> = tags.into_iter().map(HLTId::Tag).collect();

        for hlt_entry in self.entries.values_mut() {
            for id_group in hlt_entry.id_groups.iter_mut() {
                let matches_hazard = id_group.iter().any(|hlt_id| match hlt_id {
                    HLTId::OrganismName(name) => organism_name == name,
                    _ => false,
                });
                if matches_hazard {
                    if let Some((internal_tags_add, internal_tags_sub)) =
                        Self::check_internal_tag_change(&new_tags, id_group)
                    {
                        tracing::warn!(
                            "Internal tags changed, check if pipeline re-run necessary: added {:?}; subtracted {:?}",
                            internal_tags_add,
                            internal_tags_sub,
                        );
                    }
                    let mut new_id_group: Vec<_> = id_group
                        .iter()
                        .filter(|hlt_id| !matches!(hlt_id, HLTId::Tag(_)))
                        .cloned()
                        .collect();
                    new_id_group.extend_from_slice(&new_tags[..]);
                    *id_group = new_id_group;
                }
            }
        }
    }

    /// Checks if:
    /// - internal tag is added from new tags to old id group
    /// - internal tag is removed from old id group (because it isn't in new tags)
    ///
    /// returns (added_tags, subtracted_tags) if either list is populated, but None if both are
    /// empty.
    fn check_internal_tag_change(
        new_tags: &[HLTId],
        old_id_group: &[HLTId],
    ) -> Option<(Vec<HLTId>, Vec<HLTId>)> {
        let internal_new_tags: HashSet<_> = new_tags
            .iter()
            .filter(|hlt_id| matches!(hlt_id, HLTId::Tag(tag) if tag.is_internal()))
            .collect();
        let internal_old_id_group: HashSet<_> = old_id_group
            .iter()
            .filter(|hlt_id| matches!(hlt_id, HLTId::Tag(tag) if tag.is_internal()))
            .collect();

        let internal_tags_add = internal_new_tags.difference(&internal_old_id_group);
        let internal_tags_sub = internal_old_id_group.difference(&internal_new_tags);

        if internal_tags_add.clone().count() + internal_tags_sub.clone().count() != 0 {
            Some((
                internal_tags_add.map(|id| (*id).clone()).collect(),
                internal_tags_sub.map(|id| (*id).clone()).collect(),
            ))
        } else {
            None
        }
    }

    /// For every id_group containing HltId { OrganismName: organism_name }
    /// - add an HltId::Tiled if tiled arg is true, after removing any existing HltId::Tiled
    /// - remove any HltId::Tiled if tiled arg is false
    ///
    /// Will move HltId::Tiled if it already exists; this simplifies the implementation.
    pub fn set_tiled(&mut self, organism_name: &str, tiled: bool) {
        for hlt_entry in self.entries.values_mut() {
            for id_group in hlt_entry.id_groups.iter_mut() {
                let matches_hazard = id_group.iter().any(|hlt_id| match hlt_id {
                    HLTId::OrganismName(name) => organism_name == name,
                    _ => false,
                });
                if matches_hazard {
                    let mut new_id_group: Vec<_> = id_group
                        .iter()
                        .filter(|hlt_id| !matches!(hlt_id, HLTId::Tiled))
                        .cloned()
                        .collect();
                    if tiled {
                        new_id_group.push(HLTId::Tiled);
                    }
                    *id_group = new_id_group;
                }
            }
        }
    }

    /// For every id_group containing HltId { OrganismName: organism_name }
    /// - add an HltId::OrganismType("hazard type"), after removing any existing HltId::OrganismType
    ///
    /// Will move HltId::OrganismType if it already exists; this simplifies the implementation.
    pub fn set_organism_type(&mut self, organism_name: &str, organism_type: OrganismType) {
        for hlt_entry in self.entries.values_mut() {
            for id_group in hlt_entry.id_groups.iter_mut() {
                let matches_hazard = id_group.iter().any(|hlt_id| match hlt_id {
                    HLTId::OrganismName(name) => organism_name == name,
                    _ => false,
                });
                if matches_hazard {
                    let mut new_id_group: Vec<_> = id_group
                        .iter()
                        .filter(|hlt_id| !matches!(hlt_id, HLTId::OrganismType(_)))
                        .cloned()
                        .collect();
                    new_id_group.push(HLTId::OrganismType(organism_type));
                    *id_group = new_id_group;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// set_tags should completely replace tags for only the specified hazard
    /// No other HLTId should be affected
    /// Currently set_tags implementation preserves hltid order and pushes tags on end.
    /// Test is order-dependent.
    #[test]
    fn test_set_tags() {
        const OLD_TAG_1: Tag = Tag::HumanToHuman;
        const OLD_TAG_2: Tag = Tag::ArthropodToHuman;
        const NEW_TAG_1: Tag = Tag::SelectAgentHhs;
        const NEW_TAG_2: Tag = Tag::SelectAgentUsda;

        let mut hlt = HazardLookupTable {
            entries: [
                (
                    1,
                    HLTEntry::new(vec![vec![
                        HLTId::OrganismName("Test Virus 1".into()),
                        HLTId::Accession("AN010101".into()),
                        HLTId::Tag(OLD_TAG_1),
                        HLTId::Tag(OLD_TAG_2),
                    ]]),
                ),
                (
                    2,
                    HLTEntry::new(vec![
                        vec![
                            HLTId::OrganismName("Test Virus 2".into()),
                            HLTId::Accession("AN020202".into()),
                            HLTId::Tag(OLD_TAG_1),
                            HLTId::Tag(OLD_TAG_2),
                        ],
                        vec![
                            HLTId::OrganismName("Test Virus 2".into()),
                            HLTId::Accession("AN020202".into()),
                            HLTId::Tag(OLD_TAG_1),
                        ],
                    ]),
                ),
            ]
            .into_iter()
            .collect(),
            merge_cache: HashMap::default(),
        };

        let expected = HazardLookupTable {
            entries: [
                (
                    1,
                    HLTEntry::new(vec![vec![
                        HLTId::OrganismName("Test Virus 1".into()),
                        HLTId::Accession("AN010101".into()),
                        HLTId::Tag(OLD_TAG_1),
                        HLTId::Tag(OLD_TAG_2),
                    ]]),
                ),
                (
                    2,
                    HLTEntry::new(vec![
                        vec![
                            HLTId::OrganismName("Test Virus 2".into()),
                            HLTId::Accession("AN020202".into()),
                            HLTId::Tag(NEW_TAG_1),
                            HLTId::Tag(NEW_TAG_2),
                            HLTId::Tag(Tag::SdnaLowRiskDNA),
                        ],
                        vec![
                            HLTId::OrganismName("Test Virus 2".into()),
                            HLTId::Accession("AN020202".into()),
                            HLTId::Tag(NEW_TAG_1),
                            HLTId::Tag(NEW_TAG_2),
                            HLTId::Tag(Tag::SdnaLowRiskDNA),
                        ],
                    ]),
                ),
            ]
            .into_iter()
            .collect(),
            merge_cache: HashMap::default(),
        };

        hlt.set_tags(
            "Test Virus 2",
            vec![NEW_TAG_1, NEW_TAG_2, Tag::SdnaLowRiskDNA],
        );
        assert_eq!(hlt, expected);
    }

    #[test]
    fn test_set_tiled() {
        // - 1, Tiled -> Tiled
        // - 2, Tiled -> untiled
        // - 3, untiled -> Tiled
        // - 4, untiled -> untiled
        let mut hlt = HazardLookupTable {
            entries: [
                (
                    1,
                    HLTEntry::new(vec![
                        // Doubled to make sure it covers each hlt_id_group
                        vec![HLTId::OrganismName("Test Virus 1".into()), HLTId::Tiled],
                        vec![HLTId::OrganismName("Test Virus 1".into()), HLTId::Tiled],
                    ]),
                ),
                (
                    2,
                    HLTEntry::new(vec![
                        vec![HLTId::OrganismName("Test Virus 2".into()), HLTId::Tiled],
                        vec![HLTId::OrganismName("Test Virus 2".into()), HLTId::Tiled],
                    ]),
                ),
                (
                    3,
                    HLTEntry::new(vec![
                        // Doubled to make sure it covers each hlt_id_group
                        vec![HLTId::OrganismName("Test Virus 3".into())],
                        vec![HLTId::OrganismName("Test Virus 3".into())],
                    ]),
                ),
                (
                    4,
                    HLTEntry::new(vec![
                        vec![HLTId::OrganismName("Test Virus 4".into())],
                        vec![HLTId::OrganismName("Test Virus 4".into())],
                    ]),
                ),
            ]
            .into_iter()
            .collect(),
            merge_cache: HashMap::default(),
        };

        let expected = HazardLookupTable {
            entries: [
                (
                    1,
                    HLTEntry::new(vec![
                        // Doubled to make sure it covers each hlt_id_group
                        vec![HLTId::OrganismName("Test Virus 1".into()), HLTId::Tiled],
                        vec![HLTId::OrganismName("Test Virus 1".into()), HLTId::Tiled],
                    ]),
                ),
                (
                    2,
                    HLTEntry::new(vec![
                        vec![HLTId::OrganismName("Test Virus 2".into())],
                        vec![HLTId::OrganismName("Test Virus 2".into())],
                    ]),
                ),
                (
                    3,
                    HLTEntry::new(vec![
                        // Doubled to make sure it covers each hlt_id_group
                        vec![HLTId::OrganismName("Test Virus 3".into()), HLTId::Tiled],
                        vec![HLTId::OrganismName("Test Virus 3".into()), HLTId::Tiled],
                    ]),
                ),
                (
                    4,
                    HLTEntry::new(vec![
                        vec![HLTId::OrganismName("Test Virus 4".into())],
                        vec![HLTId::OrganismName("Test Virus 4".into())],
                    ]),
                ),
            ]
            .into_iter()
            .collect(),
            merge_cache: HashMap::default(),
        };

        hlt.set_tiled("Test Virus 1", true);
        hlt.set_tiled("Test Virus 2", false);
        hlt.set_tiled("Test Virus 3", true);
        hlt.set_tiled("Test Virus 4", false);
        assert_eq!(hlt, expected);
    }

    #[test]
    fn test_set_organism_type() {
        // - 1, no organism_type
        // - 2, organism_type already exists and is changed
        // - 3, organism_type already exists and is not changed.
        let mut hlt = HazardLookupTable {
            entries: [
                (
                    1,
                    HLTEntry::new(vec![
                        // Doubled to make sure it covers each hlt_id_group
                        vec![HLTId::OrganismName("Test Virus 1".into())],
                        vec![HLTId::OrganismName("Test Virus 1".into())],
                    ]),
                ),
                (
                    2,
                    HLTEntry::new(vec![
                        vec![
                            HLTId::OrganismName("Test Virus 2".into()),
                            HLTId::OrganismType(OrganismType::Toxin),
                        ],
                        vec![
                            HLTId::OrganismName("Test Virus 2".into()),
                            HLTId::OrganismType(OrganismType::Toxin),
                        ],
                    ]),
                ),
                (
                    3,
                    HLTEntry::new(vec![
                        // Doubled to make sure it covers each hlt_id_group
                        vec![
                            HLTId::OrganismName("Test Virus 3".into()),
                            HLTId::OrganismType(OrganismType::Virus),
                        ],
                        vec![
                            HLTId::OrganismName("Test Virus 3".into()),
                            HLTId::OrganismType(OrganismType::Virus),
                        ],
                    ]),
                ),
            ]
            .into_iter()
            .collect(),
            merge_cache: HashMap::default(),
        };

        let expected = HazardLookupTable {
            entries: [
                (
                    1,
                    HLTEntry::new(vec![
                        // Doubled to make sure it covers each hlt_id_group
                        vec![
                            HLTId::OrganismName("Test Virus 1".into()),
                            HLTId::OrganismType(OrganismType::Virus),
                        ],
                        vec![
                            HLTId::OrganismName("Test Virus 1".into()),
                            HLTId::OrganismType(OrganismType::Virus),
                        ],
                    ]),
                ),
                (
                    2,
                    HLTEntry::new(vec![
                        vec![
                            HLTId::OrganismName("Test Virus 2".into()),
                            HLTId::OrganismType(OrganismType::Virus),
                        ],
                        vec![
                            HLTId::OrganismName("Test Virus 2".into()),
                            HLTId::OrganismType(OrganismType::Virus),
                        ],
                    ]),
                ),
                (
                    3,
                    HLTEntry::new(vec![
                        // Doubled to make sure it covers each hlt_id_group
                        vec![
                            HLTId::OrganismName("Test Virus 3".into()),
                            HLTId::OrganismType(OrganismType::Virus),
                        ],
                        vec![
                            HLTId::OrganismName("Test Virus 3".into()),
                            HLTId::OrganismType(OrganismType::Virus),
                        ],
                    ]),
                ),
            ]
            .into_iter()
            .collect(),
            merge_cache: HashMap::default(),
        };

        hlt.set_organism_type("Test Virus 1", OrganismType::Virus);
        hlt.set_organism_type("Test Virus 2", OrganismType::Virus);
        hlt.set_organism_type("Test Virus 3", OrganismType::Virus);
        assert_eq!(hlt, expected);
    }

    #[test]
    fn test_check_internal_tag_change() {
        type Hlt = HazardLookupTable;

        assert_eq!(Hlt::check_internal_tag_change(&[], &[]), None);
        assert_eq!(
            Hlt::check_internal_tag_change(
                &[
                    HLTId::Tag(Tag::SdnaLowRiskDNA),
                    HLTId::Tag(Tag::HumanToHuman)
                ],
                &[
                    HLTId::Tag(Tag::SdnaLowRiskDNA),
                    HLTId::Tag(Tag::ArthropodToHuman)
                ]
            ),
            None
        );

        {
            // change: sdna tag added
            let new_tags = &[HLTId::Tag(Tag::SdnaLowRiskDNA)];
            let old_id_group = &[];
            assert_eq!(
                Hlt::check_internal_tag_change(new_tags, old_id_group),
                Some((vec![HLTId::Tag(Tag::SdnaLowRiskDNA)], vec![],))
            );
        }
        {
            // change: sdna tag removed
            let new_tags = &[];
            let old_id_group = &[HLTId::Tag(Tag::SdnaLowRiskDNA)];
            assert_eq!(
                Hlt::check_internal_tag_change(new_tags, old_id_group),
                Some((vec![], vec![HLTId::Tag(Tag::SdnaLowRiskDNA)]))
            );
        }
    }
}
