use super::*;

#[test]
fn query_params_are_percent_decoded() {
    assert_eq!(
        parse_query_param("q=hello%20world", "q").as_deref(),
        Some("hello world")
    );
    assert_eq!(
        parse_query_param("q=%E4%BE%8B%E5%AD%90", "q").as_deref(),
        Some("例子")
    );
}

#[test]
fn invalid_percent_encoding_is_rejected() {
    assert!(parse_query_param("q=%zz", "q").is_none());
}

#[test]
fn dashboard_defers_archive_queries_until_range_commit() {
    assert!(DASHBOARD_HTML.contains("oninput=\"previewArchiveRange('start')\""));
    assert!(DASHBOARD_HTML.contains("onchange=\"commitArchiveRange()\""));
    assert!(DASHBOARD_HTML.contains("function selectArchiveFile(name)"));
    assert!(DASHBOARD_HTML.contains("setArchiveRange("));
    assert!(DASHBOARD_HTML.contains("function resetArchiveRange()"));
}

#[test]
fn safe_filename_rejects_path_traversal() {
    assert!(!safe_history_filename("../etc/passwd"));
    assert!(!safe_history_filename("other-1234.msgpack.gz")); // wrong prefix
    assert!(!safe_history_filename("querylog-1234/x.msgpack.gz")); // slash
    assert!(safe_history_filename(
        "querylog-00001749000000000000.msgpack.gz"
    ));
    assert!(safe_history_filename(
        "querylog-00001749000000000000.msgpack"
    ));
}
