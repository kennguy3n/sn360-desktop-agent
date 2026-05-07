//! In-memory catalogue store and verification helpers.
//!
//! `sda-software` keeps the parsed [`Manifest`] (post-signature
//! check) in a small in-process cache so the action orchestrator can
//! look an artefact up by id without re-fetching for every install /
//! update / uninstall job. The network fetch itself is intentionally
//! NOT in this module — it lands in Phase 2.6 alongside the
//! action-executor wiring. Phase 2.5 (this scaffold) only ships the
//! verifier surface so unit tests can drive the catalogue with
//! hand-crafted manifest bytes.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::manifest::{Artefact, Manifest, ManifestError};

/// Verified catalogue snapshot. `id -> Artefact`.
#[derive(Debug, Clone, Default)]
pub struct Catalogue {
    pub catalogue_id: String,
    pub revision: u64,
    pub artefacts: BTreeMap<String, Artefact>,
}

impl Catalogue {
    /// Build a [`Catalogue`] from a verified manifest. Per-artefact
    /// SHA-256 well-formedness is enforced here so consumers can rely
    /// on `verify_sha256` being shape-checked at lookup time.
    pub fn from_manifest(manifest: Manifest) -> Result<Self, ManifestError> {
        let mut by_id = BTreeMap::new();
        for art in manifest.artefacts {
            // Cheap hex shape check — full SHA-256 mismatch is only
            // checkable with the bytes in hand.
            if crate::manifest::parse_hex_fixed::<32>(&art.sha256).is_none() {
                return Err(ManifestError::ArtefactHashShape { id: art.id.clone() });
            }
            by_id.insert(art.id.clone(), art);
        }
        Ok(Self {
            catalogue_id: manifest.catalogue_id,
            revision: manifest.revision,
            artefacts: by_id,
        })
    }

    /// Look up an artefact by id. Returns `None` if the catalogue
    /// does not approve that id.
    pub fn get(&self, id: &str) -> Option<&Artefact> {
        self.artefacts.get(id)
    }

    /// Iterate all approved artefacts.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Artefact)> {
        self.artefacts.iter()
    }
}

/// Thread-safe in-process holder for the most recently verified
/// catalogue. Replaced atomically each time the agent successfully
/// fetches and verifies a fresh manifest.
#[derive(Debug, Default, Clone)]
pub struct CatalogueStore {
    inner: Arc<RwLock<Option<Catalogue>>>,
}

impl CatalogueStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify `bytes` against the pinned key, parse, and atomically
    /// replace the cached catalogue. Returns the new revision on
    /// success.
    pub fn verify_and_swap(
        &self,
        bytes: &[u8],
        pinned_pubkey_hex: &str,
    ) -> Result<u64, ManifestError> {
        let manifest = Manifest::parse(bytes)?;
        manifest.verify_signature(pinned_pubkey_hex)?;
        let revision = manifest.revision;
        let cat = Catalogue::from_manifest(manifest)?;
        let mut guard = self.inner.write().expect("catalogue store rwlock poisoned");
        *guard = Some(cat);
        Ok(revision)
    }

    /// Snapshot the current catalogue, if any.
    pub fn snapshot(&self) -> Option<Catalogue> {
        self.inner
            .read()
            .expect("catalogue store rwlock poisoned")
            .clone()
    }

    /// Convenience: look up an artefact in the latest catalogue.
    pub fn get(&self, id: &str) -> Option<Artefact> {
        self.inner
            .read()
            .expect("catalogue store rwlock poisoned")
            .as_ref()
            .and_then(|c| c.get(id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Artefact, Manifest, MANIFEST_SCHEMA_VERSION};
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_manifest(signing_key: &SigningKey, revision: u64) -> (Vec<u8>, String) {
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let mut m = Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            catalogue_id: "sn360-test".into(),
            revision,
            artefacts: vec![Artefact {
                id: "Mozilla.Firefox".into(),
                name: "Mozilla Firefox".into(),
                version: "120.0".into(),
                url: "https://example.test/firefox".into(),
                sha256: "0".repeat(64),
                approval_state: "Approved".into(),
            }],
            key_id: pubkey_hex.clone(),
            signature: String::new(),
        };
        // Sign over the canonical pre-image; canonical_pre_image
        // blanks `signature` itself, so we don't need to do it here.
        let pre = m.canonical_pre_image().unwrap();
        let sig = signing_key.sign(&pre);
        m.signature = hex::encode(sig.to_bytes());
        let bytes = serde_json::to_vec(&m).unwrap();
        (bytes, pubkey_hex)
    }

    #[test]
    fn store_swaps_atomically_on_success() {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let (bytes, pub_hex) = signed_manifest(&signing_key, 1);
        let store = CatalogueStore::new();
        let rev = store.verify_and_swap(&bytes, &pub_hex).unwrap();
        assert_eq!(rev, 1);
        assert!(store.get("Mozilla.Firefox").is_some());
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn store_keeps_old_catalogue_when_new_fetch_fails_signature() {
        let signing_key = SigningKey::from_bytes(&[4u8; 32]);
        let (good, pub_hex) = signed_manifest(&signing_key, 1);
        let store = CatalogueStore::new();
        store.verify_and_swap(&good, &pub_hex).unwrap();

        // Tamper a fresh manifest's body so the signature won't
        // verify.
        let signing_key2 = SigningKey::from_bytes(&[5u8; 32]);
        let (bad_bytes, _other_pub) = signed_manifest(&signing_key2, 2);
        // Verify against the *original* pinned key — fails.
        assert!(store.verify_and_swap(&bad_bytes, &pub_hex).is_err());
        // Old catalogue still in place.
        assert_eq!(store.snapshot().unwrap().revision, 1);
    }

    #[test]
    fn from_manifest_rejects_malformed_artefact_hash() {
        let m = Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            catalogue_id: "c".into(),
            revision: 0,
            artefacts: vec![Artefact {
                id: "bad".into(),
                name: "B".into(),
                version: "1".into(),
                url: "u".into(),
                sha256: "not-hex".into(),
                approval_state: "Approved".into(),
            }],
            key_id: "k".into(),
            signature: "s".into(),
        };
        assert!(matches!(
            Catalogue::from_manifest(m),
            Err(ManifestError::ArtefactHashShape { .. })
        ));
    }

    #[test]
    fn from_manifest_indexes_by_id() {
        let m = Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            catalogue_id: "c".into(),
            revision: 5,
            artefacts: vec![
                Artefact {
                    id: "a".into(),
                    name: "A".into(),
                    version: "1".into(),
                    url: "u".into(),
                    sha256: "0".repeat(64),
                    approval_state: "Approved".into(),
                },
                Artefact {
                    id: "b".into(),
                    name: "B".into(),
                    version: "2".into(),
                    url: "u".into(),
                    sha256: "1".repeat(64),
                    approval_state: "Approved".into(),
                },
            ],
            key_id: "k".into(),
            signature: "s".into(),
        };
        let cat = Catalogue::from_manifest(m).unwrap();
        assert_eq!(cat.revision, 5);
        assert_eq!(cat.artefacts.len(), 2);
        assert_eq!(cat.get("a").unwrap().version, "1");
        assert_eq!(cat.get("b").unwrap().version, "2");
        assert!(cat.get("c").is_none());
    }
}
