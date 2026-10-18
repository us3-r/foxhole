// Foxhole-owned evidence rules. These matches never independently assign a verdict.
rule foxhole_harmless_test_marker : fixture {
    meta:
        description = "Purpose-built harmless verification marker"
        version = "1"
    strings:
        $marker = "FOXHOLE_HARMLESS_TEST"
    condition:
        $marker
}
rule foxhole_upx_section_marker : context {
    meta:
        description = "UPX section marker; packing is contextual evidence"
        version = "1"
    strings:
        $mz = { 4d 5a }
        $section = "UPX0"
    condition:
        $mz at 0 and $section
}
