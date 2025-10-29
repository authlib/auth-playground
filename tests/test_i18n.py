def test_invalid_language_code_raises_404(unconfigured_test_client):
    """Test that accessing an invalid language code returns 404."""
    res = unconfigured_test_client.get("/de/")
    assert res.status_code == 404


def test_valid_language_codes_work(unconfigured_test_client):
    """Test that valid language codes work correctly."""
    res_en = unconfigured_test_client.get("/en/server")
    assert res_en.status_code == 200

    res_fr = unconfigured_test_client.get("/fr/server")
    assert res_fr.status_code == 200
