# auth-python

[![Build Status](https://travis-ci.org/openstax/auth-python.svg?branch=master)](https://travis-ci.org/openstax/auth-python)

## Debugging

This project can use `ipdb`.  When running tests, make sure to use the `-s` option to prevent pytest from capturing output.

`python -m pytest -s tests -k 'test_decrypts'`
