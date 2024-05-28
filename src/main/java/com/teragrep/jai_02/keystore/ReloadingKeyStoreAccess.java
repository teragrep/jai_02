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

import javax.annotation.Nonnull;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.UnrecoverableEntryException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class ReloadingKeyStoreAccess implements IKeyStoreAccess {
    private IKeyStoreAccess ksa;
    private final LoadingCache<Long, IKeyStoreAccess> loadingCache;
    public ReloadingKeyStoreAccess(IKeyStoreAccess ksa, long secs) {
        this.ksa = ksa;

        CacheLoader<Long, IKeyStoreAccess> cacheLoader = new CacheLoader<Long, IKeyStoreAccess>() {
            @Override
            public IKeyStoreAccess load(@Nonnull Long key) {
                return new KeyStoreAccess(
                        new KeyStoreFactory(ksa.keyStorePath(), ksa.keyStorePassword()).build(),
                        ksa.keyStorePath(), ksa.keyStorePassword()
                );
            }
        };

        this.loadingCache = CacheBuilder
                .newBuilder()
                .maximumSize(1L)
                .refreshAfterWrite(secs, TimeUnit.SECONDS)
                .build(cacheLoader);
    }

    public PasswordEntry loadKey(final String username) throws UnrecoverableEntryException, KeyStoreException, InvalidKeyException {
        try {
            return loadingCache.get(0L).loadKey(username);
        } catch (ExecutionException e) {
            throw new KeyStoreException("Could not access KeyStore, loadKey failed: ", e);
        }
    }

    public void saveKey(final String username, final char[] password) throws KeyStoreException {
        try {
            loadingCache.get(0L).saveKey(username, password);
        } catch (ExecutionException e) {
            throw new KeyStoreException("Could not access KeyStore, saveKey failed: ", e);
        }
    }

    public boolean verifyKey(final String username, final char[] password) throws UnrecoverableEntryException, InvalidKeySpecException, KeyStoreException, InvalidKeyException {
        try {
            return loadingCache.get(0L).verifyKey(username, password);
        } catch (ExecutionException e) {
            throw new KeyStoreException("Could not access KeyStore, verifyKey failed: ", e);
        }
    }

    public int deleteKey(final String usernameToRemove) throws KeyStoreException, IOException {
        try {
            return loadingCache.get(0L).deleteKey(usernameToRemove);
        } catch (ExecutionException e) {
            throw new KeyStoreException("Could not access KeyStore, deleteKey failed: ", e);
        }
    }

    public boolean checkForExistingAlias(final String usernameToCheck) throws KeyStoreException {
        try {
            return loadingCache.get(0L).checkForExistingAlias(usernameToCheck);
        } catch (ExecutionException e) {
            throw new KeyStoreException("Could not access KeyStore, checkForExistingAlias failed: ", e);
        }
    }

    @Override
    public String keyStorePath() {
        return ksa.keyStorePath();
    }

    @Override
    public char[] keyStorePassword() {
        return ksa.keyStorePassword();
    }
}
