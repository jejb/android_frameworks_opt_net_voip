// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (C) 2023 James.Bottomley@HansenPartnership.com
 */

package android.net.rtp;

import java.util.Arrays;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import android.annotation.NonNull;

/**
 * This class defines a collection of encryptions to be used with
 * {@link AudioStream}s. Their parameters are designed to be exchanged
 * using Session Description Protocol (SDP) which is described in
 * RFC4566 and RFC4568 (security extensions including a=crypto:
 * parameter).  The crypto strings come from RFC3711 (AES_CM) and
 * RFC7714 (AES_GCM) and the tag values match those defined by IANA
 * for DTLS.  Note the media in a remote offer may not have tags
 * matching the IANA ones, so validity is by crypto string only.
 *
 * This class is simplified to eliminate components not used by
 * asterisk such as key lifetime and Master Key Index (MKI).
 *
 * @see AudioStream
 */
public class Crypto {
    /**
     * The RTP payload type of the encoding.
     */
    private int tag;
    private final String cipher;
    private final byte[] key;
    /*
     * Should have lifetime and MKI here, but this has only been
     * tested with asterisk which doesn't do either
     */

    @NonNull
    private static final Crypto CM_32 = new Crypto(2, "AES_CM_128_HMAC_SHA1_32", 30);
    @NonNull
    private static final Crypto CM_80 = new Crypto(1, "AES_CM_128_HMAC_SHA1_80", 30);
    @NonNull
    private static final Crypto GCM_16 = new Crypto(7, "AEAD_AES_128_GCM", 28);
    @NonNull
    private static final Crypto GCM_8 = new Crypto(9, "AEAD_AES_128_GCM_8", 28);

    @NonNull
    private static final Crypto[] sCryptos = { GCM_16, GCM_8, CM_80, CM_32 };

    /*
     * This can be called with just a cipher suite, in which case we
     * populate the key or with an entire rest of line, in which case
     * we pick up the key from it (and ignore any lifetime or MKI
     * parameters)
     */
    public Crypto(int tag, @NonNull String rest) {
        this.tag = tag;
        String[] splits = rest.split(" ");
        this.cipher = splits[0];

        if (!splits[1].startsWith("inline:"))
            throw new IllegalArgumentException("SDP a=crypto: Key string does not start with inline: but \"" + splits[1] + "\"");
        String[] keys = splits[1].substring(7).split("\\|");
        this.key = Base64.getDecoder().decode(keys[0]);
        // ignore lifetime and MKI
    }

    private Crypto(int tag, String cipher, int keylen) {
        this.tag = tag;
        this.key = new byte[keylen];
        new Random().nextBytes(this.key);
        this.cipher = cipher;
    }

    /**
     * Returns system supported Cryptos
     */
    @NonNull
    public static List<Crypto> getCryptos() {
	return Arrays.asList(sCryptos);
    }

    public int getTag() {
        return tag;
    }

    @NonNull
    public String getCipher() {
        return cipher;
    }

    @NonNull
    public byte[] getKey() {
        return key;
    }

    @NonNull
    public String getRest() {
        String bkey = new String(Base64.getEncoder().encode(key));

        return cipher + " inline:" + bkey;
    }
    public boolean valid() {
        for (Crypto s : sCryptos) {
            if (cipher.equals(s.cipher))
                return true;
        }
        return false;
    }

    public String toString() {
        return getTag() + " " + getRest();
    }
}
