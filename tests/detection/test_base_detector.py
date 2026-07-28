import pytest

from detection.base_detector import BaseDetector


def test_base_detector_cannot_be_instantiated():

    with pytest.raises(TypeError):
        BaseDetector()