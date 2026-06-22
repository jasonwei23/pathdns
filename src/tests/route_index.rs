use super::*;

#[test]
fn tag_memo_packs_sixty_four_tags_per_chunk() {
    let empty = TagMemo::new(0);
    assert!(empty.chunks.is_empty());

    let inline = TagMemo::new(64);
    assert_eq!(inline.chunks.len(), 1);
    assert!(!inline.chunks.spilled());

    let two_chunks = TagMemo::new(65);
    assert_eq!(two_chunks.chunks.len(), 2);
}

#[test]
fn tag_memo_chunk_tracks_seen_and_matched_independently() {
    let mut memo = TagMemo::new(64);
    let false_bit = 1u64 << 7;
    let true_bit = 1u64 << 42;

    memo.chunks[0].seen |= false_bit | true_bit;
    memo.chunks[0].matched |= true_bit;

    assert_ne!(memo.chunks[0].seen & false_bit, 0);
    assert_eq!(memo.chunks[0].matched & false_bit, 0);
    assert_ne!(memo.chunks[0].matched & true_bit, 0);
}
