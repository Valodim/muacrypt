# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
"""Tests for Crypto"""

from __future__ import unicode_literals

import pytest


class TestCrypto:
    def test_gen_key_and_get_keydata(self, crypto):
        keyhandle = crypto.gen_secret_key(emailadr="hello@xyz.org")
        skey_data = crypto.get_secret_keydata(keyhandle, armor=True)
        packets = crypto.list_packets(skey_data)
        assert len(packets) == 5
        assert packets[0][0] == "secret key packet"
        assert packets[1][0] == "user ID packet"
        # NOTE: the correct string here is not " <hello@xyz.org>"
        assert packets[1][1] == '"hello@xyz.org"'
        assert packets[2][0] == "signature packet"
        assert packets[3][0] == "secret sub key packet"
        assert packets[4][0] == "signature packet"

        pkey_data = crypto.get_public_keydata(keyhandle)
        packets = crypto.list_packets(pkey_data)
        assert len(packets) == 5
        assert packets[0][0] == "public key packet" == packets[0][0]
        assert packets[1][0] == "user ID packet"
        # NOTE: the correct string here is not " <hello@xyz.org>"
        assert packets[1][1] == '"hello@xyz.org"'
        assert packets[2][0] == "signature packet"
        assert packets[3][0] == "public sub key packet"
        assert packets[4][0] == "signature packet"

    def test_list_secret_keyhandles(self, crypto):
        keyhandle = crypto.gen_secret_key(emailadr="hello@xyz.org")
        l = crypto.list_secret_keyinfos(keyhandle)
        assert len(l) == 2
        assert l[0].id == keyhandle

    def test_list_public_keyhandles(self, crypto):
        keyhandle = crypto.gen_secret_key(emailadr="hello@xyz.org")
        l = crypto.list_public_keyinfos(keyhandle)
        assert len(l) == 2
        assert l[0].match(keyhandle)

    @pytest.mark.parametrize("armor", [True, False])
    def test_transfer_key_and_encrypt_decrypt_roundtrip(self, crypto,
                                                        armor):
        keyhandle = crypto.gen_secret_key(emailadr="hello@xyz.org")
        # FIXME: nothing is done with priv_keydata in test_bingpg (nor here)
        # priv_keydata = crypto.get_secret_keydata(keyhandle=keyhandle,
        #                                          armor=armor)
        public_keydata = crypto.get_public_keydata(keyhandle=keyhandle,
                                                   armor=armor)
        keyhandle2 = crypto.import_keydata(public_keydata)
        assert keyhandle2 == keyhandle

        out_encrypt = crypto.encrypt(b"123", recipients=[keyhandle])
        out, decrypt_info = crypto.decrypt(out_encrypt)
        assert out == b"123"
        assert len(decrypt_info) == 1
        k = decrypt_info[0]
        assert str(k)
        assert k.bits == 2048
        assert k.type == "RSAEncryptOrSign"
        assert k.date_created
        keyinfos = crypto.list_public_keyinfos(keyhandle)
        for keyinfo in keyinfos:
            if keyinfo.match(k.id):
                break
        else:
            pytest.fail("decryption key {!r} not found in {}".
                        format(k.id, keyinfos))

    def test_gen_key_and_sign_verify(self, crypto):
        keyhandle = crypto.gen_secret_key(emailadr="hello@xyz.org")
        sig = crypto.sign(b"123", keyhandle=keyhandle)
        keyhandle_verified = crypto.verify(data=b'123', signature=sig)
        i = min(len(keyhandle_verified), len(keyhandle))
        assert keyhandle[-i:] == keyhandle_verified[-i:]
