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

import com.teragrep.jai_02.keystore.CachingKeyStoreAccess;
import com.teragrep.jai_02.keystore.KeyStoreAccess;
import com.teragrep.jai_02.keystore.KeyStoreFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.UnrecoverableEntryException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ExecutionException;

public class CachingKeyStoreAccessTest {

    private static String keyStorePath = "target/keystore.p12";
    private static String keyStorePassword = "changeit";
    private static String userName = "trusted-12";
    private static String userPassWord = "XOsAqIhmKUTwWMjWwDaYmVgR8sl_l70H1oDPBw9z2yY";

    private static CachingKeyStoreAccess cksa;
    @BeforeAll
    public static void prepare() {
        Assertions.assertDoesNotThrow(() -> {
            cksa = new CachingKeyStoreAccess(
                    new KeyStoreAccess(
                            new KeyStoreFactory(keyStorePath, keyStorePassword.toCharArray()).build(),
                            keyStorePath, keyStorePassword.toCharArray()), 10L);

            cksa.deleteKey(userName);
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
}

