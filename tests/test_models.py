from scradar.models import Component


def test_purl_pypi_normalizes_name():
    c = Component(name="Django_Cors_Headers", version="4.9.0", ecosystem="PyPI", direct=True, depth=1)
    assert c.purl == "pkg:pypi/django-cors-headers@4.9.0"


def test_purl_npm_plain():
    c = Component(name="lodash", version="4.17.21", ecosystem="npm", direct=True, depth=1)
    assert c.purl == "pkg:npm/lodash@4.17.21"


def test_purl_npm_scoped():
    c = Component(name="@vue/test-utils", version="2.5.1", ecosystem="npm", direct=True, depth=1)
    assert c.purl == "pkg:npm/%40vue/test-utils@2.5.1"


def test_key_ignores_version():
    a = Component(name="lodash", version="4.17.15", ecosystem="npm", direct=True, depth=1)
    b = Component(name="lodash", version="4.17.21", ecosystem="npm", direct=False, depth=3)
    assert a.key == b.key == "npm:lodash"
