import stat

import pytest

from netaudit.credentials import (
    CredentialsError,
    Login,
    dump,
    load_credentials,
    merge_into,
    read_csv,
    resolve,
)

NASTY = ["p@ss:word#1", "it's", "{{ jinja }}", "0123", "yes", "  spaces  ", "%s;,\\", "-dash"]

DEFAULT = Login("netops", "default-pass", "")


def test_resolve_order_site_address_name():
    credentials = {
        "hq": {"username": "site-user", "password": "site-pass"},
        "10.0.0.2": {"password": "ip-pass"},
        "sw2": {"enable": "sw2-enable"},
    }
    assert resolve(credentials, DEFAULT, "hq", "10.0.0.1", "sw1") == Login("site-user", "site-pass", "")
    assert resolve(credentials, DEFAULT, "hq", "10.0.0.2", "sw2") == Login("site-user", "ip-pass", "sw2-enable")
    assert resolve(credentials, DEFAULT, "branch", "10.1.0.1", "br1") == DEFAULT
    assert resolve({}, DEFAULT, None, "") == DEFAULT


def test_secret_falls_back_to_the_password():
    assert Login("u", "p").secret == "p"
    assert Login("u", "p", "e").secret == "e"


def test_load_validates(tmp_path):
    path = tmp_path / "credentials.yml"
    assert load_credentials(path) == {}
    assert load_credentials(None) == {}
    path.write_text("sw1:\n  password: 0123\n")
    with pytest.raises(CredentialsError, match="put the password of 'sw1' in quotes"):
        load_credentials(path)
    path.write_text("sw1:\n  pasword: 'x'\n")
    with pytest.raises(CredentialsError, match="unknown setting pasword"):
        load_credentials(path)
    path.write_text("$ANSIBLE_VAULT;1.1;AES256\n6162\n")
    with pytest.raises(CredentialsError, match="ansible-vault"):
        load_credentials(path)
    path.write_text("sw1:\n  password: 'ok'\nsw2:\n")
    assert load_credentials(path) == {"sw1": {"password": "ok"}}


def test_dump_round_trips_any_password(tmp_path):
    entries = {f"sw{i}": {"username": "admin", "password": p} for i, p in enumerate(NASTY)}
    entries["10.0.0.9"] = {"password": "by-ip"}
    entries["yes"] = {"password": "a site called yes"}
    path = tmp_path / "credentials.yml"
    path.write_text(dump(entries))
    assert load_credentials(path) == entries


def test_csv_import_merges_and_protects_the_file(tmp_path):
    csv_path = tmp_path / "passwords.csv"
    csv_path.write_text(
        "Switch;Username;Password;Enable\nhq-acc-01;admin;p@ss,word#1;\n10.0.0.12;;'quoted';en\n;;ignored;\n",
        encoding="utf-8",
    )
    # semicolon-separated (Excel in many locales), so a password may contain commas
    entries = read_csv(csv_path)
    assert entries == {
        "hq-acc-01": {"username": "admin", "password": "p@ss,word#1"},
        "10.0.0.12": {"password": "'quoted'", "enable": "en"},
    }
    target = tmp_path / "inventory" / "credentials.yml"
    target.parent.mkdir()
    target.write_text("hq-acc-01:\n  enable: 'keep-me'\nother:\n  password: 'untouched'\n")
    assert merge_into(target, entries) == (1, 1)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert load_credentials(target) == {
        "hq-acc-01": {"enable": "keep-me", "username": "admin", "password": "p@ss,word#1"},
        "other": {"password": "untouched"},
        "10.0.0.12": {"password": "'quoted'", "enable": "en"},
    }


def test_csv_with_commas_and_quotes(tmp_path):
    csv_path = tmp_path / "passwords.csv"
    csv_path.write_text('name,password\nsw1,"has,comma ""and quotes"""\n', encoding="utf-8")
    assert read_csv(csv_path) == {"sw1": {"password": 'has,comma "and quotes"'}}


def test_csv_needs_a_switch_column(tmp_path):
    csv_path = tmp_path / "passwords.csv"
    csv_path.write_text("device,password\nsw1,x\n")
    with pytest.raises(CredentialsError, match="no switch column"):
        read_csv(csv_path)
