use super::*;

#[test]
fn pending_send_batch_respects_hot_reloaded_limit() {
    assert_eq!(pending_send_batch_len(200, 64, 64), 64);
    assert_eq!(pending_send_batch_len(200, 1, 64), 1);
    assert_eq!(pending_send_batch_len(4, 32, 64), 4);
}
