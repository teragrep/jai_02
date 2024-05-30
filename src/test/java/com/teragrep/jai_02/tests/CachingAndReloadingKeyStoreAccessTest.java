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

import com.teragrep.jai_02.entry.EntryAliasFactory;
import com.teragrep.jai_02.keystore.*;
import com.teragrep.jai_02.password.PasswordEntry;
import com.teragrep.jai_02.password.PasswordEntryFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.*;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.UnrecoverableEntryException;

public class CachingAndReloadingKeyStoreAccessTest {

    private static String keyStorePath = "target/keystore.p12";
    private static String keyStorePassword = "changeit";
    private static String userName = "trusted-12";
    private static String userPassWord = "XOsAqIhmKUTwWMjWwDaYmVgR8sl_l70H1oDPBw9z2yY";

    private static CachingKeyStoreAccess cksa;
    @BeforeAll
    public static void prepare() {
        Assertions.assertDoesNotThrow(() -> {
            cksa = new CachingKeyStoreAccess(
                    new ReloadingKeyStoreAccess(
                            new KeyStoreAccessImpl(
                                    new KeyStoreFactory(keyStorePath, keyStorePassword.toCharArray()).build(),
                                    keyStorePath, keyStorePassword.toCharArray()), 1L
                    ), 1L);
        });
    }

    public void save() {
        Assertions.assertDoesNotThrow(() -> {
            cksa.saveKey(
                    userName,
                    userPassWord.toCharArray());
        });
    }

    public void verify() {
        Assertions.assertDoesNotThrow(() -> {
            boolean authOk = cksa.verifyKey(
                    userName,
                    userPassWord.toCharArray());

            Assertions.assertTrue(authOk);
        });
    }

    @Test
    public void saveAndVerifyTest() {
        save();
        verify();
    }

    @Test
    public void externalModification_Delete_Test() {
        Assertions.assertDoesNotThrow(() -> {
            cksa.deleteKey(userName);
            cksa.saveKey(userName, userPassWord.toCharArray());
            Files.deleteIfExists(Paths.get(keyStorePath));
            Thread.sleep(2000); // KeyStore refreshes every second
        });

        // key should not exist
        Assertions.assertThrows(InvalidKeyException.class, () -> {
            cksa.loadKey(userName);
        }, "Username <[" + userName + "]> was not found in the map!");
    }

    @Test
    public void externalModification_AddEntry_Test() throws Exception {
            Assertions.assertDoesNotThrow(() -> {
                String user = "new-user";
                char[] pass = "pass".toCharArray();
                cksa.deleteKey(user);

                CachingKeyStoreAccess cksa2 = new CachingKeyStoreAccess(
                        new ReloadingKeyStoreAccess(
                                new KeyStoreAccessImpl(
                                        new KeyStoreFactory(keyStorePath, keyStorePassword.toCharArray()).build(),
                                        keyStorePath, keyStorePassword.toCharArray()), 1L
                        ), 1L);

                cksa2.saveKey(user, pass);

                Thread.sleep(2000);

                PasswordEntry ent1 = cksa.loadKey(user);
                PasswordEntry ent2 = cksa2.loadKey(user);

                Assertions.assertEquals(ent1.secretKey(), ent2.secretKey());
            });
    }
}