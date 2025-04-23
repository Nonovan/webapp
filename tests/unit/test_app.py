pytest.ini:
[pytest]
testpaths = tests
python_files = test_*.py
addopts = -v

tests/unit/test_app.py:
import pytest

def test_hello_world():
    assert 1 + 1 == 2