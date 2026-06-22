use super::*;

#[test]
fn rejects_ipv4_prefix_lengths_above_32() {
    let pair = IpSetPair {
        v4: Some("route4/33".to_string()),
        v6: None,
    };

    assert!(SetPair::parse(&pair).is_err());
}

#[test]
fn rejects_prefix_lengths_above_128() {
    assert!(SetName::parse("inet@fw4@route6@129").is_err());
}
