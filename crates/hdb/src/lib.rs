// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod consolidate_windows;
pub mod database;
pub mod entry;
pub mod exemption;
pub mod hlt;
pub mod metadata;
pub mod response;
pub mod shims;
pub mod synthesis_permission;
pub mod tags;

pub use consolidate_windows::{ConsolidatedHazardResult, DebugSeqHdbResponse, HitRegion};
pub use database::Database;
pub use entry::Entry;
pub use exemption::Exemptions;
pub use hlt::{HLTEntry, HLTId, HLTLookupError, HazardLookupTable};
pub use metadata::{Metadata, MetadataDecodeError, Provenance};
pub use response::{HdbOrganism, HdbResponse, HdbResponseError};

use shared_types::synthesis_permission::{Region, SynthesisPermission};

/// Parameters passed to the HDB alongside a query.
#[derive(Debug)]
pub struct HdbParams<'a> {
    pub region: Region,
    pub exemptions: &'a Exemptions,
}

/// Values that the HDB is configured with on startup.
pub struct HdbConfig<'a> {
    pub database: &'a Database,
    pub hlt: &'a HazardLookupTable,
}

/// Run the entire HDB flow, returning `Some(HdbResponse)` if an entry exists, and `None` otherwise.
///
/// Returns an error if there are IO or file format errors (e.g., if database files are too old or corrupted)
pub fn query_hdb(
    query: &[u8; 32],
    params: &HdbParams,
    config: &HdbConfig,
) -> Result<Option<HdbResponse>, QueryError> {
    let entry = config
        .database
        .query(query)
        .map_err(|e| QueryError::FileRead(e, *query))?;

    if let Some(entry) = entry {
        let response = entry_to_response(entry, params.region, params.exemptions, config.hlt)?;
        Ok(Some(response))
    } else {
        Ok(None)
    }
}

/// Run just the metadata extraction and response generation parts of the HDB flow.
/// Useful for, e.g., calculating different responses for different regions with the
/// same `Entry`.
///
/// Returns an error if there are file format errors (e.g., HLT is too old or corrupted).
pub fn entry_to_response(
    entry: Entry,
    region: Region,
    exemptions: &Exemptions,
    hlt: &HazardLookupTable,
) -> Result<HdbResponse, QueryError> {
    let metadata = entry
        .metadata()
        .map_err(|e| QueryError::MetadataFormat(e, entry))?;

    let mut response = HdbResponse::with_hlt(metadata, region, exemptions, hlt)
        .map_err(|e| QueryError::HdbResponse(e, metadata))?;

    if response.synthesis_permission == SynthesisPermission::Denied
        && exemptions.is_hash_exempt(&entry.hash_bytes())
    {
        response.synthesis_permission = SynthesisPermission::Granted;
        response.exempt = true;
    }

    Ok(response)
}

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("reading file for query {1:x?}: {0}")]
    FileRead(#[source] std::io::Error, [u8; 32]),
    #[error("decoding metadata for {1:x?}: {0}")]
    MetadataFormat(#[source] MetadataDecodeError, Entry),
    #[error("constructing response from {1:?}: {0}")]
    HdbResponse(#[source] HLTLookupError, Metadata),
}

#[cfg(test)]
mod test {
    use doprf::prf::HashPart;
    use pipeline_bridge::{OrganismType, Tag};

    use super::*;

    static TEST_HLT: &str = r#"
    {
        "entries": {
            "198": { "id_groups": [
                [
                    {"OrganismName": "Nastytoxin"},
                    {"OrganismType": "Toxin"},
                    {"Accession": "NC_00002"},
                    {"Tag": "SelectAgentHhs"},
                    {"Tag": "SdnaLowRiskDNA"}
                ]
            ] }
        }
    }
    "#;

    #[test]
    fn hash_exemption() {
        let hlt: HazardLookupTable = serde_json::from_str(TEST_HLT).unwrap();

        let hash = HashPart::from_rp(Default::default());
        let metadata = Metadata {
            hlt_index: 198,
            an_subindex: 0,
            an_likelihood: half::f16::from_f32(0.5),
            provenance: Provenance::AAWildType,
            reverse_screened: false,
            is_common: false,
        };

        let entry = Entry::new(hash, metadata);
        let response = entry_to_response(entry, Region::All, &Default::default(), &hlt);
        let expected_response = HdbResponse {
            synthesis_permission: SynthesisPermission::Denied,
            most_likely_organism: HdbOrganism {
                name: "Nastytoxin".into(),
                organism_type: OrganismType::Toxin,
                ans: vec!["NC_00002".into()],
                tags: vec![Tag::SelectAgentHhs],
            },
            organisms: vec![HdbOrganism {
                name: "Nastytoxin".into(),
                organism_type: OrganismType::Toxin,
                ans: vec!["NC_00002".into()],
                tags: vec![Tag::SelectAgentHhs],
            }],
            an_likelihood: 0.5,
            provenance: Provenance::AAWildType,
            reverse_screened: false,
            window_gap: 3,
            exempt: false,
        };

        assert_eq!(response.unwrap(), expected_response);

        let hash_bytes = entry.hash_bytes();
        let exemptions = Exemptions::new_unchecked(vec![], [hash_bytes].into());
        let exempt_response = entry_to_response(entry, Region::All, &exemptions, &hlt);

        assert_eq!(
            exempt_response.unwrap(),
            HdbResponse {
                synthesis_permission: SynthesisPermission::Granted,
                exempt: true,
                ..expected_response
            }
        );
    }
}
