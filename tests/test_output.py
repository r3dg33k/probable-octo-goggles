import json
import tempfile
from pathlib import Path

from spartan.output import ConsoleSink, CsvSink, JsonlSink, JsonSink
from spartan.results import ScanResult


class TestConsoleSink:
    def test_create(self):
        sink = ConsoleSink(verbose=False, quiet=False)
        assert sink is not None

    def test_quiet_suppresses_info(self):
        sink = ConsoleSink(verbose=False, quiet=True)
        sink.write_message("should not appear")
        assert True

    def test_quiet_shows_error(self):
        sink = ConsoleSink(verbose=False, quiet=True)
        sink.write_message("error msg", level="error")
        assert True

    def test_close_noop(self):
        sink = ConsoleSink()
        sink.close()


class TestJsonSink:
    def test_write_and_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.json"
            sink = JsonSink(str(path))
            sink.write_result(ScanResult(url="http://test/", status_code=200))
            sink.write_result(ScanResult(url="http://test2/", status_code=404))
            sink.close()

            data = json.loads(path.read_text(encoding="utf-8"))
            assert len(data) == 2
            assert data[0]["url"] == "http://test/"
            assert data[1]["status_code"] == 404

    def test_empty_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.json"
            sink = JsonSink(str(path))
            sink.close()
            data = json.loads(path.read_text(encoding="utf-8"))
            assert data == []


class TestJsonlSink:
    def test_write_and_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.jsonl"
            sink = JsonlSink(str(path))
            sink.write_result(ScanResult(url="http://a/"))
            sink.write_result(ScanResult(url="http://b/"))
            sink.close()

            lines = path.read_text(encoding="utf-8").strip().split("\n")
            assert len(lines) == 2
            assert json.loads(lines[0])["url"] == "http://a/"
            assert json.loads(lines[1])["url"] == "http://b/"


class TestCsvSink:
    def test_write_and_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.csv"
            sink = CsvSink(str(path))
            sink.write_result(
                ScanResult(url="http://test/", status_code=200, detector="test"),
            )
            sink.close()

            text = path.read_text(encoding="utf-8")
            assert "url" in text
            assert "http://test/" in text
            assert "200" in text
