package com.teragrep.jai_02.keystore;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class KeyStoreEntryTest {
    private static String keyStorePath = "target/keystore.p12";
    private static String keyStorePassword = "changeit";
    private static String userName = "trusted-12";
    private static String userPassWord = "XOsAqIhmKUTwWMjWwDaYmVgR8sl_l70H1oDPBw9z2yY";
    @Test
    public void keyStoreEntryTest() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyStoreEntryAccess ksea = new KeyStoreEntryAccess(
                new KeyStoreAccess(keyStorePath, keyStorePassword.toCharArray()));

        KeySecret ks = new KeySecret(new KeyFactory().build(userName));
        ksea.storeEntry(ks, userPassWord.toCharArray());

        SecretKey fetchedSecretKey = ksea.fetchEntry(ks);
        SecretKey originalSecretKey = ks.asSecretKey(userPassWord.toCharArray());

        assertEquals(originalSecretKey, fetchedSecretKey);
    }
}
