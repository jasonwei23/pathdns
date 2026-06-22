use super::*;

#[test]
fn received_queries_are_counted_once_by_protocol() {
    let ql = crate::querylog::QueryLogHandle::disabled();
    record_query_received(&ql, ClientProto::Udp);
    record_query_received(&ql, ClientProto::Tcp);
    assert_eq!(ql.counters.queries_total.load(Ordering::Relaxed), 2);
    assert_eq!(ql.counters.queries_udp.load(Ordering::Relaxed), 1);
    assert_eq!(ql.counters.queries_tcp.load(Ordering::Relaxed), 1);
}
