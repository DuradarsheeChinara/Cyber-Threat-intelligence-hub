from app.services.scanning import scan_file, scan_url


def test_url_scan_is_local_and_explainable():
    result = scan_url("https://example.com/music")
    assert result["verdict"] == "Low risk"
    assert "not opened" in result["note"]


def test_file_scan_flags_executable_and_hashes_it():
    result = scan_file("invoice.pdf.exe", b"MZ\x00\x00")
    assert result["verdict"] == "Suspicious"
    assert len(result["sha256"]) == 64
    assert any("Double-extension" in signal for signal in result["signals"])
