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

import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.HashMap;

public class KeyStoreAccess {
    protected final String keyStorePath;
    protected final char[] keyStorePassword;
    private final KeyFactory keyFactory;
    private final Map<String, String> userToAliasMapping;
    protected final KeyStore keyStore;

    public KeyStoreAccess(final String keyStorePath, final char[] keyStorePassword) {
        this(keyStorePath, keyStorePassword, new KeyFactory());
    }
    public KeyStoreAccess(final String keyStorePath, final char[] keyStorePassword, final KeyFactory keyFactory) {
        this.keyFactory = keyFactory;
        this.keyStorePassword = keyStorePassword;
        this.keyStorePath = keyStorePath;
        this.userToAliasMapping = new HashMap<>();
        this.keyStore = new KeyStoreFactory(keyStorePath, keyStorePassword).build();
    }

    public SecretKey loadKey(final String username) throws UnrecoverableEntryException, KeyStoreException, InvalidKeyException {
        // TODO 3 create a cache of requests -> success/fail

        // get alias mapping
        final String alias;
        if (userToAliasMapping.containsKey(username)) {
            alias = userToAliasMapping.get(username);
        } else {
            throw new InvalidKeyException("Username <" + username + "> was not found in the map!");
        }

        // create keyWithSecret object based on KeyString
        KeySecret keyWithSecret = new KeySecret(new KeyString(alias, keyFactory.split()).toKey());

        // Get SecretKey from keyStore and return marked with appropriate algorithm used
        return new KeyStoreEntryAccess(this).fetchEntry(keyWithSecret);
    }

    public void saveKey(final String username, final char[] pw) throws KeyStoreException {
        // Generate Key based on username and set keyStore password
        KeySecret keyWithSecret = new KeySecret(keyFactory.build(username));
        new KeyStoreEntryAccess(this).storeEntry(keyWithSecret, pw);

        // Put user->user:alias mapping and store keyStore in file
        userToAliasMapping.put(keyWithSecret.asKey().userName().userName(), keyWithSecret.asKey().toString());
    }

    public boolean verifyKey(final String username, final char[] pw) throws NoSuchAlgorithmException, InvalidKeySpecException,
            UnrecoverableEntryException, KeyStoreException, InvalidKeyException {
        // Get stored SecretKey and compare to newly generated key
        final SecretKey storedKey = loadKey(username);
        final SecretKey newKey = new KeySecret(keyFactory.build(username)).asSecretKey(pw);
        return storedKey.equals(newKey);
    }
}
