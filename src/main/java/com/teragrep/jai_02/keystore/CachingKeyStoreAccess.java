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

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import java.io.IOException;
import java.security.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * Provides access to the KeyStore, such as loading, saving
 * and deleting entries. Keeps track of the username->alias mapping
 * via the UserToAliasMapping object.
 */
public class CachingKeyStoreAccess implements KeyStoreAccess {
    private final KeyStoreAccess keyStoreAccess;

    // cache
    private final LoadingCache<UserNameAndPassword, Boolean> loadingCache;

    public CachingKeyStoreAccess(final KeyStoreAccess keyStoreAccess, final long secs) {
        this.keyStoreAccess = keyStoreAccess;

        CacheLoader<UserNameAndPassword, Boolean> cacheLoader = new CacheLoader<UserNameAndPassword, Boolean>() {

            @Override
            public Boolean load(UserNameAndPassword pe) throws Exception {
                return keyStoreAccess.verifyKey(pe.username(), pe.password());
            }
        };

        this.loadingCache = CacheBuilder.newBuilder().refreshAfterWrite(secs, TimeUnit.SECONDS).build(cacheLoader);

    }

    public PasswordEntry loadKey(final String username) throws UnrecoverableEntryException, KeyStoreException, InvalidKeyException {
        return keyStoreAccess.loadKey(username);
    }

    public void saveKey(final String username, final char[] password) throws KeyStoreException {
        keyStoreAccess.saveKey(username, password);
    }

    public boolean verifyKey(final String username, final char[] password) throws KeyStoreException {
        try {
            return loadingCache.get(new UserNameAndPassword(username, password));
        } catch (ExecutionException e) {
            throw new KeyStoreException("Could not access KeyStore: ", e);
        }
    }

    public int deleteKey(final String usernameToRemove) throws KeyStoreException, IOException {
        return keyStoreAccess.deleteKey(usernameToRemove);
    }

    public boolean checkForExistingAlias(final String usernameToCheck) throws KeyStoreException {
       return keyStoreAccess.checkForExistingAlias(usernameToCheck);
    }

    public String keyStorePath() {
        return keyStoreAccess.keyStorePath();
    }

    public char[] keyStorePassword() {
        return keyStoreAccess.keyStorePassword();
    }
}
