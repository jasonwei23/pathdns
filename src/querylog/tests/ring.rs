use super::*;

#[test]
fn zero_capacity_ring_discards_events() {
    let ring = EventRing::new(0);
    assert_eq!(ring.len(), 0);
}

#[test]
fn qps_snapshot_returns_newest_window_in_order() {
    let ring = QpsRing::new();
    ring.push(1);
    ring.push(2);
    ring.push(3);
    assert_eq!(ring.snapshot(2), vec![2, 3]);
}
