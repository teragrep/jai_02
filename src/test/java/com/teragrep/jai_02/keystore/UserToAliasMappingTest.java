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
package com.teragrep.jai_02.keystore;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;

public class UserToAliasMappingTest {
    private static String keyStorePath = "target/keystore.p12";
    private static String keyStorePassword = "changeit";
    private static String userName = "trusted-12";
    private static String userPassWord = "XOsAqIhmKUTwWMjWwDaYmVgR8sl_l70H1oDPBw9z2yY";
    private static KeyStoreAccess ksa;

    @BeforeAll
    public static void prepare() {
        ksa = new KeyStoreAccess(new KeyStoreFactory(keyStorePath, keyStorePassword.toCharArray()).build(), keyStorePath, keyStorePassword.toCharArray());
    }

    @Test
    public void saveAndReloadTest() {
        Assertions.assertDoesNotThrow(() -> {
            // Delete any pre-existing saves for username and save again
            ksa.deleteKey(userName);
            ksa.saveKey(userName, userPassWord.toCharArray());
            // Check that 'loadKey()' loads the same key even though called twice
            SecretKey originalKey = ksa.loadKey(userName).secretKey();
            SecretKey newKey = ksa.loadKey(userName).secretKey();
            Assertions.assertEquals(originalKey, newKey);
        });
    }

    @Test
    public void saveFailTest() {
        Assertions.assertDoesNotThrow(() -> {
            ksa.deleteKey(userName);
            ksa.saveKey(userName, userPassWord.toCharArray());
        });

        // Should throw on second save with same username
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ksa.saveKey(userName, userPassWord.toCharArray()));
    }

    @Test
    public void saveNoAliasFailTest() {
        Assertions.assertDoesNotThrow(() -> {
            ksa.deleteKey(userName);
        });

        Assertions.assertThrows(InvalidKeyException.class, () -> ksa.loadKey(userName));
    }
}
