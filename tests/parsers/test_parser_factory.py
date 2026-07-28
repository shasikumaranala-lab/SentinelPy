import pytest

from config.constants import LogSource
from parsers.linux_parser import LinuxParser
from parsers.parser_factory import ParserFactory


def test_linux_parser_creation():

    parser = ParserFactory.get_parser(LogSource.LINUX)

    assert isinstance(parser, LinuxParser)


def test_unknown_parser():

    class FakeSource:
        value = "UNKNOWN"

    with pytest.raises(ValueError):
        ParserFactory.get_parser(FakeSource())