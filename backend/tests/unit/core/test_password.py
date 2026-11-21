import hashlib

from app.core.password import hash_password, needs_rehash, verify_password


def test_un_mot_de_passe_hache_est_reconnu():
    stored = hash_password("correct horse")

    assert verify_password("correct horse", stored)
    assert not verify_password("wrong horse", stored)


def test_un_ancien_hash_sha256_est_encore_accepte_mais_doit_etre_rehache():
    legacy = hashlib.sha256(b"old-secret").hexdigest()

    assert verify_password("old-secret", legacy)
    assert needs_rehash(legacy)


def test_un_hash_bcrypt_n_a_pas_besoin_d_etre_rehache():
    assert not needs_rehash(hash_password("x"))


def test_un_hash_stocke_non_ascii_ne_fait_pas_planter_la_verification():
    assert not verify_password("x", "hash-é")
