import pytest

from threat_intelligence.base_provider import BaseProvider


def test_base_provider_is_abstract():

    with pytest.raises(TypeError):

        BaseProvider()