import json
import pytest
import ipdb

from oxauth import Strategy2

SIGNATURE_PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxItufComL1S+j+U2JVr4\n"
    "aeIPyZYJR8S3RcxXjlHgybrAsBf/zyAjJlOBIhVfrm9jUF1HKNMyiTKQehG5XBBW\n"
    "/F8DQT5vGdBd4g9WIAmNU0E+symeF4X+mFIZ6dYwTMKtZxv1U0nkJ8xL2q4jCFVB\n"
    "UMlQRmz9EffSz+fmXr9xGQj80HKahzciM6m2aspX096qUP90155qmLEayE2uhs5C\n"
    "oAUbahA+VXS6ggsCUeVyog5Z1mC086d8r78ylr1y8IQ3aazdJE/mKxfqvu9S423h\n"
    "wNzBP6Fp0n68ZjUdUirqAZEbSrioJgFLEzX8ef7XilTL9dKLSS1w09ErctAF+Tor\n"
    "hwIDAQAB\n"
    "-----END PUBLIC KEY-----"
)

def test_decrypts_good_cookie(mocker):
    # These "secrets" are copied from local development environment Accounts defaults.
    # They are not used in real deployments.

    cookie = ("eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..tD56OCg6Un6gzkTy.eQAZrea_ORzHiFvg3rmEjxjmRXlqhXIfOYA55RQP9T"
              "uum2S7d-KqFQiNEVHvdOAz8Jt1UULezUllc1bJ42j7IiBlakUm8VlOIhS6n0XtobmuQkIV7nd_0_DNTn2uvmLC70Z9pGtgUOFm3q"
              "XtQa5DczQTuoTQ56-_M9uewyIYtj_B0H0bfjDNvsj92hf54K8o486B97qnvfGIkb7jXRUk3q6Aa_NtNIqbmCR9Tac29H9rn7CAcV"
              "TG2vzG-kfUwpxrA9A-LlkX4SX1LKzsD3TVQe-05Xv9cQdf8zArdeE_9KJGAdbRlM-DVK3ul2YBTy4z92uxY4cA7vtNsANb1ByNn7"
              "K5zEa4Mnb1OcxhhrPKTTkyVWtt4-w8GhmZl48kBoeQTWEEXtRlksabKe5RhHu3-i3dXvbWBp6ALXjEkAoKC-BDDjCUt_IOErp_g0"
              "G1CnD3aRU--lqvm2IJnKq1sncTd8qtFTm91MRPzg94O0-OHk7NohktEz3DtJjKeH0EdW98d_mon8OAf4xJDtXrADE-VxAMPhNzoF"
              "s6o2k4t3BJpIvUj9AGuAx46vkk7B0TeIAXFy8dhq6n5vvFdYnoih1BM47DnOv5DZtABlvQv5xJTfyN23jb-QDKG-AZ--zjtamtkT"
              "r_7GASXqbQy2xEw2QA0yQCUS6JhnRRCcrC913CU8uPtjMbzWoxkCZjCyxQkX1fcVddU9e3pmay9LZ4zZolVCOwWUp1TuEgYwSweN"
              "pR4WiwGiWelMhHSZ3QYKjJpGyIkzCSkn7ZQRLLTe0joU43figYs790TPx4waUfwi5r3AED6OSkfxTBsjgOR9DY6083CpCZ4N7lea"
              "XhsfepgwjiwzVw5TB4YGRg275AE4lZhdKf1lgS7OSk1S7NeMkv88ZDHnVIVAd0wiR9PZf36Ni48CArfC4btn6DT7cQURQOnQTQyi"
              "K-WvFfkEMdWX7_Z-GRG9CCnVIT3CBBZnvoIcCaUbVmXRqv0cFJmvfsmGsA.FJxz84tw7BCYCrwYeqLpdQ")

    strategy = Strategy2(signature_public_key=SIGNATURE_PUBLIC_KEY,
                         signature_algorithm="RS256",
                         encryption_private_key="RvGHVZ/kvzUAA5Z3t68+FNhuMCJxkzv+",
                         encryption_algorithm="dir",
                         encryption_method="A256GCM")

    payload = strategy.decrypt(cookie)

    assert payload.user_uuid == '1b2dc73a-a792-462b-9b0f-59bd22bac26d'

def test_decrypts_bad_cookie(mocker):
    cookie = ("badness..here.sdfs.")

    strategy = Strategy2(signature_public_key=SIGNATURE_PUBLIC_KEY,
                         signature_algorithm="RS256",
                         encryption_private_key="RvGHVZ/kvzUAA5Z3t68+FNhuMCJxkzv+",
                         encryption_algorithm="dir",
                         encryption_method="A256GCM")

    payload = strategy.decrypt(cookie)

    assert payload == None

def test_logs_decryption_error(mocker):
    log_spy = mocker.patch('logging.exception')

    cookie = ("badness..here.sdfs.")

    strategy = Strategy2(signature_public_key=SIGNATURE_PUBLIC_KEY,
                         signature_algorithm="RS256",
                         encryption_private_key="RvGHVZ/kvzUAA5Z3t68+FNhuMCJxkzv+",
                         encryption_algorithm="dir",
                         encryption_method="A256GCM",
                         logging_enabled=True)

    payload = strategy.decrypt(cookie)

    log_spy.assert_called_once()

def test_only_allows_A256GCM(mocker):
    with pytest.raises(ValueError):
        Strategy2(signature_public_key=SIGNATURE_PUBLIC_KEY,
                  signature_algorithm="RS256",
                  encryption_private_key="RvGHVZ/kvzUAA5Z3t68+FNhuMCJxkzv+",
                  encryption_algorithm="foo",
                  encryption_method="A256GCM")

def test_only_allows_dir(mocker):
    with pytest.raises(ValueError):
        Strategy2(signature_public_key=SIGNATURE_PUBLIC_KEY,
                  signature_algorithm="RS256",
                  encryption_private_key="RvGHVZ/kvzUAA5Z3t68+FNhuMCJxkzv+",
                  encryption_algorithm="dir",
                  encryption_method="foo")

