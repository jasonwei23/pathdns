use super::*;

#[test]
fn empty_ipset_batch_is_a_noop() {
    let request = NetfilterRequest::IpsetAddBatch {
        name: "test",
        ips: &[],
        mask: None,
    };
    assert!(request.encode(1).is_empty());
}

fn error_message(errno: i32) -> Vec<u8> {
    let mut data = vec![0u8; 20];
    data[16..20].copy_from_slice(&errno.to_ne_bytes());
    data
}

#[test]
fn ipset_test_only_maps_not_present_to_false() {
    assert!(!decode_ipset_test(NLMSG_ERROR, &error_message(-IPSET_ERR_EXIST)).unwrap());
    assert!(decode_ipset_test(NLMSG_ERROR, &error_message(-libc::EPERM)).is_err());
}

#[test]
fn nft_test_only_maps_enoent_to_false() {
    assert!(!decode_nft_test(NLMSG_ERROR, &error_message(-libc::ENOENT)).unwrap());
    assert!(decode_nft_test(NLMSG_ERROR, &error_message(-libc::EPERM)).is_err());
}

#[test]
fn truncated_error_messages_are_rejected() {
    assert!(decode_ipset_test(NLMSG_ERROR, &[0; 19]).is_err());
    assert!(decode_nft_test(NLMSG_ERROR, &[0; 19]).is_err());
}

#[test]
fn apply_mask_v4() {
    use std::net::Ipv4Addr;
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 100));
    assert_eq!(apply_mask(ip, 24), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0)));
    assert_eq!(apply_mask(ip, 16), IpAddr::V4(Ipv4Addr::new(1, 2, 0, 0)));
    assert_eq!(apply_mask(ip, 32), ip);
    assert_eq!(apply_mask(ip, 0), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
}

#[test]
fn apply_mask_v6() {
    use std::net::Ipv6Addr;
    let ip = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap());
    let net = apply_mask(ip, 32);
    assert_eq!(net, IpAddr::V6("2001:db8::".parse::<Ipv6Addr>().unwrap()));
}

#[test]
fn prefix_end_v4() {
    use std::net::Ipv4Addr;
    let net = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0));
    assert_eq!(prefix_end(net, 24), IpAddr::V4(Ipv4Addr::new(1, 2, 4, 0)));
    assert_eq!(prefix_end(net, 32), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 1)));
}
