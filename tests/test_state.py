import tempfile
from pathlib import Path

from spartan.state import ScanState


class TestScanState:
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = ScanState(Path(tmp))
            state.add_url("http://test/url1")
            state.add_url("http://test/url2")
            state.add_scanned("http://test/url1")
            state.save()

            state2 = ScanState(Path(tmp))
            assert state2.load() is True
            assert state2.urls == ["http://test/url1", "http://test/url2"]
            assert state2.scanned_urls == ["http://test/url1"]

    def test_load_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = ScanState(Path(tmp))
            assert state.load() is False

    def test_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = ScanState(Path(tmp))
            state.metadata = {"target": "http://test/"}
            state.save()

            state2 = ScanState(Path(tmp))
            state2.load()
            assert state2.metadata.get("target") == "http://test/"

    def test_no_duplicate_urls(self):
        state = ScanState(Path("/tmp/_test_state_xyz"))
        state.add_url("http://test/")
        state.add_url("http://test/")
        assert len(state.urls) == 1

    def test_add_scanned(self):
        state = ScanState(Path("/"))
        state.add_scanned("http://test/")
        assert "http://test/" in state.scanned_urls
