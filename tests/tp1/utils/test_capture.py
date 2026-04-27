from unittest.mock import patch
from src.tp1.utils.capture import Capture


def test_capture_init():
    capture = Capture()

    assert capture.interface == ""
    assert capture.summary == ""


def test_given_capture_when_capture_traffic_then_interface_is_set():
    capture = Capture()

    capture.capture_traffic()

    assert capture.interface == ""


def test_sort_network_protocols():
    capture = Capture()

    result = capture.sort_network_protocols()

    assert result == ""


def test_get_all_protocols():
    capture = Capture()

    result = capture.get_all_protocols()

    assert result == ""


def test_analyse():
    capture = Capture()

    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"


def test_get_summary():
    capture = Capture()
    capture.summary = "Test summary"

    result = capture.get_summary()

    assert result == "Test summary"


def test_gen_summary():
    capture = Capture()

    result = capture._gen_summary()

    assert result == ""
