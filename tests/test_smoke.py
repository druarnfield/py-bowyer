"""Phase 0 sanity check: the package imports and exposes a version."""

import bowyer


def test_package_imports():
    assert bowyer.__version__
