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

package com.teragrep.jai_02.tests;

import com.teragrep.jai_02.keystore.KeyStoreAccessImpl;
import com.teragrep.jai_02.keystore.KeyStoreFactory;
import com.teragrep.jai_02.password.PasswordEntry;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

public class KeyStoreAccessImplTest {

    private static String keyStorePath = "target/keystore.p12";
    private static String keyStorePassword = "changeit";
    private static String userName = "trusted-12";
    private static String userPassWord = "XOsAqIhmKUTwWMjWwDaYmVgR8sl_l70H1oDPBw9z2yY";

    private static KeyStoreAccessImpl ksa;
    @BeforeAll
    public static void prepare() {
        Assertions.assertDoesNotThrow(() -> {
            ksa = new KeyStoreAccessImpl(new KeyStoreFactory(keyStorePath, keyStorePassword.toCharArray()).build(), keyStorePath, keyStorePassword.toCharArray());
            ksa.deleteKey(userName);
        });
    }

    @Test
    public void saveAndVerifyTest() {
        Assertions.assertDoesNotThrow(() -> {
            ksa.saveKey(
                    userName,
                    userPassWord.toCharArray());

            boolean authOk = ksa.verifyKey(
                    userName,
                    userPassWord.toCharArray());

            Assertions.assertTrue(authOk);
        });
    }

    @Test
    public void aliasAlreadyExistsTest() {
        Assertions.assertDoesNotThrow(() -> {
            ksa.saveKey(
                    userName,
                    userPassWord.toCharArray());
        });

        IllegalArgumentException saveKeyThrownException = Assertions.assertThrows(IllegalArgumentException.class, () -> {
            ksa.saveKey(
                    userName,
                    userPassWord.toCharArray());
        });

        Assertions.assertEquals("Alias for username <[" + userName + "]> already exists in KeyStore!",
                saveKeyThrownException.getMessage());
    }

    @Test
    public void loadNonExistingEntryTest() {
        Assertions.assertDoesNotThrow(() -> {
            ksa.deleteKey(userName);
        });

        InvalidKeyException ike = Assertions.assertThrows(InvalidKeyException.class, () -> {
            ksa.loadKey(userName);
        }, "LoadKey with username <[" + userName + "]> did not fail as expected, key was found");

        Assertions.assertEquals("Username <[" + userName + "]> was not found in the map!", ike.getMessage());
    }

    @Test
    public void usernameCaseSensitivityTest() {
        String user0 = "userNAME";
        String user1 = "username";
        // Make sure existing entries do not exist by deleting them
        // Save user0 to KeyStore
        Assertions.assertDoesNotThrow(() -> {
            ksa.deleteKey(user0);
            ksa.deleteKey(user1);
            ksa.saveKey(user0, "password".toCharArray());
        });

        // Try loading user1 from KeyStore, should fail as they are in different cases
        InvalidKeyException ike = Assertions.assertThrows(InvalidKeyException.class, () -> {
            ksa.loadKey(user1);
        });

        Assertions.assertEquals("Username <[" + user1 + "]> was not found in the map!", ike.getMessage());
    }

    @Test
    public void externalModificationAddEntryTest() {
        // One keyStoreAccess reads the key and one saves it
        // Tests modification of the same keyStore from multiple sources
        Assertions.assertDoesNotThrow(() -> {
            KeyStoreAccessImpl readingKeyStoreAccess = new KeyStoreAccessImpl(
                                    new KeyStoreFactory(keyStorePath, keyStorePassword.toCharArray()).build(),
                                    keyStorePath, keyStorePassword.toCharArray());

            String user = "new-user";
            char[] pass = "pass".toCharArray();

            // Delete user
            readingKeyStoreAccess.deleteKey(user);

            final KeyStoreAccessImpl modifyingKeyStoreAccess = new KeyStoreAccessImpl(
                    new KeyStoreFactory(keyStorePath, keyStorePassword.toCharArray()).build(),
                    keyStorePath, keyStorePassword.toCharArray());
            // Save user from another keyStoreAccess object
            modifyingKeyStoreAccess.saveKey(user, pass);

            Thread.sleep(1500);
            // Force keyStore file reload
            readingKeyStoreAccess = new KeyStoreAccessImpl(
                    new KeyStoreFactory(keyStorePath, keyStorePassword.toCharArray()).build(),
                    keyStorePath, keyStorePassword.toCharArray());

            // Read user from initial keyStoreAccess object
            // This will throw a InvalidKeyException if none found and
            // test will fail
            PasswordEntry ent1 = readingKeyStoreAccess.loadKey(user);
            // Should be non-null always
            Assertions.assertNotNull(ent1.secretKey());
        });
    }
}

