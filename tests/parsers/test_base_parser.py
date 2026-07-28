import pytest

from parsers.base_parser import BaseParser


def test_base_parser_cannot_be_instantiated():

    with pytest.raises(TypeError):

        BaseParser()