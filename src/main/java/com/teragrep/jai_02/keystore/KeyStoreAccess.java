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
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.UnrecoverableEntryException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

/**
 * Provides access to the KeyStore, such as loading, saving
 * and deleting entries. Keeps track of the username->alias mapping
 * via the UserToAliasMapping object.
 */
public class KeyStoreAccess {
    private final String keyStorePath;
    private final char[] keyStorePassword;
    private final EntryAliasFactory entryAliasFactory;
    private final UserToAliasMapping userToAliasMapping;
    private final KeyStore keyStore;

    public KeyStoreAccess(final String keyStorePath, final char[] keyStorePassword) {
        this(keyStorePath, keyStorePassword, new EntryAliasFactory());
    }
    public KeyStoreAccess(final String keyStorePath, final char[] keyStorePassword, final EntryAliasFactory entryAliasFactory) {
        this.entryAliasFactory = entryAliasFactory;
        this.keyStorePassword = keyStorePassword;
        this.keyStorePath = keyStorePath;
        this.keyStore = new KeyStoreFactory(keyStorePath, keyStorePassword).build();
        this.userToAliasMapping = new UserToAliasMapping(new KeyStoreEntryAccess(this), this.entryAliasFactory.split());
    }

    public EntryAliasValuePair loadKey(final String username) throws UnrecoverableEntryException, KeyStoreException, InvalidKeyException {
        // TODO create a cache of requests -> success/fail
        final String alias;
        if (userToAliasMapping.has(username)) {
            alias = userToAliasMapping.get(username);
        } else {
            throw new InvalidKeyException("Username <[" + username + "]> was not found in the map!");
        }

        EntryAliasSecretKeyFactory keyWithSecret = new EntryAliasSecretKeyFactory(new EntryAliasString(alias, entryAliasFactory.split()).toEntryAlias());
        return new EntryAliasValuePair(
                keyWithSecret.asEntryAlias(),
                new KeyStoreEntryAccess(this).fetchEntry(keyWithSecret)
        );
    }

    public void saveKey(final String username, final char[] password) throws KeyStoreException {
        // Generate Key based on username and set keyStore password
        boolean aliasAlreadyExists = checkForExistingAlias(username);
        if (aliasAlreadyExists) {
            throw new IllegalArgumentException("Alias for username <[" + username + "]> already exists in KeyStore!");
        }
        EntryAliasSecretKeyFactory keyWithSecret = new EntryAliasSecretKeyFactory(entryAliasFactory.build(username));
        new KeyStoreEntryAccess(this).storeEntry(keyWithSecret, password);

        // Put user->user:alias mapping and store keyStore in file
        userToAliasMapping.put(keyWithSecret.asEntryAlias().userName().toString(), keyWithSecret.asEntryAlias().toString());
    }

    public boolean verifyKey(final String username, final char[] password) throws InvalidKeySpecException,
            UnrecoverableEntryException, KeyStoreException, InvalidKeyException {
        // Get stored SecretKey and compare to newly generated key with same salt
        final EntryAliasValuePair storedKeyPair = loadKey(username);
        final SecretKey newKey = new EntryAliasSecretKeyFactory(entryAliasFactory.build(username, storedKeyPair.entryAlias().salt())).build(password);
        return storedKeyPair.secretKey().equals(newKey);
    }

    public int deleteKey(final String usernameToRemove) throws KeyStoreException, IOException {
        final Enumeration<String> aliases = keyStore.aliases();
        final List<String> aliasesToRemove = new ArrayList<>();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            final EntryAliasString entryAliasString = new EntryAliasString(alias, entryAliasFactory.split());

            final String username = entryAliasString.toEntryAlias().userName().toString();
            if (username.equals(usernameToRemove)) {
                aliasesToRemove.add(alias);
            }
        }

        KeyStoreEntryAccess ksea = new KeyStoreEntryAccess(this);
        for (String alias : aliasesToRemove) {
            ksea.deleteEntry(alias);
        }

        userToAliasMapping.remove(usernameToRemove);

        return aliasesToRemove.size();
    }

    private boolean checkForExistingAlias(final String usernameToCheck) throws KeyStoreException {
        boolean exists = false;

        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            final EntryAliasString entryAliasString = new EntryAliasString(alias, entryAliasFactory.split());

            final String username = entryAliasString.toEntryAlias().userName().toString();
            if (username.equals(usernameToCheck)) {
                exists = true;
                break;
            }
        }

        return exists;
    }

    public KeyStore keyStore() {
        return this.keyStore;
    }

    public String keyStorePath() {
        return this.keyStorePath;
    }

    public char[] keyStorePassword() {
        return this.keyStorePassword;
    }
}
