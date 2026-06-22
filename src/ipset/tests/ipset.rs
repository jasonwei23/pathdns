use super::config::SetName;
use super::worker::{dedup_jobs, AddJob};
use std::net::{IpAddr, Ipv4Addr};

fn make_jobs(pairs: &[(&str, IpAddr)]) -> Vec<AddJob> {
    pairs
        .iter()
        .map(|(set, ip)| AddJob {
            set: SetName::IpSet {
                name: set.to_string(),
                mask: None,
            },
            ip: *ip,
            interval: false,
        })
        .collect()
}

#[test]
fn dedup_jobs_removes_adjacent_duplicates_after_sort() {
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let mut jobs = make_jobs(&[("s", ip), ("s", ip), ("s", ip)]);
    jobs.sort_by(|a, b| a.set.cmp(&b.set).then_with(|| a.ip.cmp(&b.ip)));
    dedup_jobs(&mut jobs);
    assert_eq!(jobs.len(), 1);
}

#[test]
fn dedup_jobs_keeps_different_ips() {
    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
    let mut jobs = make_jobs(&[("s", ip1), ("s", ip2)]);
    jobs.sort_by(|a, b| a.set.cmp(&b.set).then_with(|| a.ip.cmp(&b.ip)));
    dedup_jobs(&mut jobs);
    assert_eq!(jobs.len(), 2);
}

/// Live latency probe for sync nftset adds. Requires root and a pre-created
/// nft set; only runs when PATHDNS_LIVE_NFT is set. Example:
///   nft add table inet testt
///   nft add set inet testt host '{ type ipv4_addr; }'
///   nft add set inet testt iv '{ type ipv4_addr; flags interval; }'
///   PATHDNS_LIVE_NFT='inet@testt@host inet@testt@iv@24' \
///     cargo test --bin pathdns live_nftset_add_latency -- --ignored --nocapture
#[test]
#[ignore]
fn live_nftset_add_latency() {
    let Ok(spec) = std::env::var("PATHDNS_LIVE_NFT") else {
        eprintln!("set PATHDNS_LIVE_NFT to a space-separated list of nftset specs");
        return;
    };
    let interval_flag = std::env::var("PATHDNS_LIVE_INTERVAL").is_ok();
    for raw in spec.split_whitespace() {
        let set = SetName::parse(raw).expect("parse set");
        let mut client = super::client::NetfilterClient::new().expect("open netlink");
        let ips = [IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40))];
        let t0 = std::time::Instant::now();
        let res = client.add_many(&set, &ips, interval_flag);
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        eprintln!("add {raw} (interval={interval_flag}) -> {res:?} in {ms:.3} ms");
    }
}
