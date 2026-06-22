use super::*;

fn make_cache(ttl_secs: u64) -> VerdictCache {
    VerdictCache::new(Some(&VerdictCacheConfig {
        capacity: 1000,
        ttl: Duration::from_secs(ttl_secs),
    }))
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pathdns-test-{}-{}", std::process::id(), name))
}

#[test]
fn save_load_roundtrip() {
    let path = temp_path("roundtrip");
    let a = make_cache(3600);
    a.add("primary.example.com", true);
    a.add("secondary.example.com", false);
    let saved = a.save_to_file(&path, 42).unwrap();
    assert_eq!(saved, 2);

    let b = make_cache(3600);
    let loaded = b.load_from_file(&path, 42).unwrap();
    assert_eq!(loaded, 2);
    assert_eq!(b.get("primary.example.com"), Some(true));
    assert_eq!(b.get("secondary.example.com"), Some(false));
    assert_eq!(b.get("unknown.example.com"), None);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fingerprint_mismatch_rejected() {
    let path = temp_path("fp-mismatch");
    let a = make_cache(3600);
    a.add("example.com", true);
    a.save_to_file(&path, 1).unwrap();

    let b = make_cache(3600);
    assert!(b.load_from_file(&path, 2).is_err());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn expired_entries_skipped_on_load() {
    let path = temp_path("expired");
    // ttl=1s: write an entry whose deadline has already passed by crafting the
    // file via a cache whose entries are saved, then loading after expiry.
    let a = make_cache(1);
    a.add("example.com", true);
    a.save_to_file(&path, 7).unwrap();

    std::thread::sleep(Duration::from_millis(1100));
    let b = make_cache(1);
    let loaded = b.load_from_file(&path, 7).unwrap();
    assert_eq!(loaded, 0);
    assert_eq!(b.get("example.com"), None);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn zero_ttl_never_expires() {
    let path = temp_path("zero-ttl");
    let a = make_cache(0);
    a.add("example.com", false);
    a.save_to_file(&path, 9).unwrap();

    let b = make_cache(0);
    let loaded = b.load_from_file(&path, 9).unwrap();
    assert_eq!(loaded, 1);
    assert_eq!(b.get("example.com"), Some(false));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn invalidate_all_removes_cached_verdicts() {
    let cache = make_cache(0);
    cache.add("example.com", true);
    assert_eq!(cache.get("example.com"), Some(true));

    cache.invalidate_all();

    assert_eq!(cache.get("example.com"), None);
}

#[test]
fn disabled_cache_saves_nothing() {
    let c = VerdictCache::new(None);
    assert_eq!(c.save_to_file(Path::new("/nonexistent"), 0).unwrap(), 0);
}
