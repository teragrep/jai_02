/*
 * Java Authentication Info jai_02
 * Copyright (C) 2021  Suomen Kanuuna Oy
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://github.com/teragrep/teragrep/blob/main/LICENSE>.
 *
 *
 * Additional permission under GNU Affero General Public License version 3
 * section 7
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with other code, such other code is not for that reason alone subject to any
 * of the requirements of the GNU Affero GPL version 3 as long as this Program
 * is the same Program as licensed from Suomen Kanuuna Oy without any additional
 * modifications.
 *
 * Supplemented terms under GNU Affero General Public License version 3
 * section 7
 *
 * Origin of the software must be attributed to Suomen Kanuuna Oy. Any modified
 * versions must be marked as "Modified version of" The Program.
 *
 * Names of the licensors and authors may not be used for publicity purposes.
 *
 * No rights are granted for use of trade names, trademarks, or service marks
 * which are in The Program if any.
 *
 * Licensee must indemnify licensors and authors for any liability that these
 * contractual assumptions impose on licensors and authors.
 *
 * To the extent this program is licensed as part of the Commercial versions of
 * Teragrep, the applicable Commercial License may apply to this file if you as
 * a licensee so wish it.
 */
package com.teragrep.jai_02;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

public class KeyStoreCredentialLookup {

    private static final String keyalgo = "PBKDF2WithHmacSHA1";
    private static final byte[] salt = "foofoofo".getBytes(StandardCharsets.UTF_8);

    public KeyStoreCredentialLookup() {

    }

    private static SecretKey createSecretKey(String userPassWord) throws InvalidKeySpecException, NoSuchAlgorithmException {
        // example password
        char[] password = userPassWord.toCharArray();

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 100_000, 160);

        SecretKeyFactory skf = SecretKeyFactory.getInstance(keyalgo);
        SecretKey pbeKey = skf.generateSecret(pbeKeySpec); // encyptionKey for the password
        return pbeKey;
    }

    public static void save(String keyStorePath, String keyStorePassword, String userName, String userPassWord)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null); // Initialize a blank keystore

        SecretKey pbeKey = createSecretKey(userPassWord);

        // only keystore password protects the entry
        KeyStore.PasswordProtection passwordPasswordProtection = new KeyStore.PasswordProtection(
                keyStorePassword.toCharArray());

        keyStore.setEntry(userName, new KeyStore.SecretKeyEntry(pbeKey), passwordPasswordProtection);

        // save keystore with a password
        char[] keystorePassword = keyStorePassword.toCharArray();
        keyStore.store(new FileOutputStream(keyStorePath), keystorePassword);
    }

    public static boolean verifyKey(InputStream inputStream, String keyStorePassword, String userName, String userPassWord)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableEntryException, InvalidKeySpecException {

        SecretKey storedKey = loadKeyImpl(inputStream, keyStorePassword, userName);
        SecretKey newKey = createSecretKey(userPassWord);

        return storedKey.equals(newKey);
    }

    private static SecretKey loadKeyImpl(
            InputStream inputStream,
            String keyStorePassword,
            String userName
    ) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
            UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(inputStream, keyStorePassword.toCharArray());

        System.out.println(
                "ks has these: "
        );
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements()) {
            System.out.println(aliases.nextElement());
        }
        // TODO 1 concatenate the salt into the alias -> alias:salt and be done with it?
        // TODO 2 create a lookup list that maps alias -> alias:salt for accessing them?
        // TODO 3 create a cache of requests -> success/fail

        KeyStore.PasswordProtection passwordPasswordProtection = new KeyStore.PasswordProtection(
                keyStorePassword.toCharArray());

        KeyStore.SecretKeyEntry ske = (KeyStore.SecretKeyEntry) ks.getEntry(userName, passwordPasswordProtection);

        System.out.println("keylen in bits encoded: " + ske.getSecretKey().getEncoded().length*Byte.SIZE + " in bytes: " + ske.getSecretKey().getEncoded().length);
        System.out.println(ske.toString());

        /*
        SecretKeyFactory factory = SecretKeyFactory.getInstance(keyalgo);
        PBEKeySpec keySpec = (PBEKeySpec) factory.getKeySpec(ske.getSecretKey(), PBEKeySpec.class);
         */

        //return new String(keySpec.getPassword());
        return ske.getSecretKey();
    }
}
