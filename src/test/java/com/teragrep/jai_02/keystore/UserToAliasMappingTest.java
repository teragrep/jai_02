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
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.UnrecoverableEntryException;
import java.util.Arrays;

public class UserToAliasMappingTest {
    private static String keyStorePath = "target/keystore.p12";
    private static String keyStorePassword = "changeit";
    private static String userName = "trusted-12";
    private static String userPassWord = "XOsAqIhmKUTwWMjWwDaYmVgR8sl_l70H1oDPBw9z2yY";

    @Test
    public void saveAndReloadTest() throws KeyStoreException, UnrecoverableEntryException, InvalidKeyException {
        SecretKey originalKey = save();
        SecretKey newKey = load();
        System.out.println(Arrays.toString(originalKey.getEncoded()) + " " + originalKey.getAlgorithm() + " " + originalKey.getFormat());
        System.out.println(Arrays.toString(newKey.getEncoded()) + " " + newKey.getAlgorithm() + " " + newKey.getFormat());

        // FIXME: Need to differentiate between multiple keys for same user as they can have different keys in KeyStore?
        Assertions.assertEquals(originalKey, newKey);
    }

    private SecretKey save() throws UnrecoverableEntryException, KeyStoreException, InvalidKeyException {
        KeyStoreAccess access = new KeyStoreAccess(keyStorePath, keyStorePassword.toCharArray());
        access.saveKey(userName, userPassWord.toCharArray());
        return access.loadKey(userName);
    }

    private SecretKey load() throws UnrecoverableEntryException, KeyStoreException, InvalidKeyException {
        KeyStoreAccess access = new KeyStoreAccess(keyStorePath, keyStorePassword.toCharArray());
        return access.loadKey(userName);
    }
}
