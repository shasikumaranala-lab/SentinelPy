import pytest

from reports.base_reporter import BaseReporter


def test_base_reporter_is_abstract():

    with pytest.raises(TypeError):
        BaseReporter()