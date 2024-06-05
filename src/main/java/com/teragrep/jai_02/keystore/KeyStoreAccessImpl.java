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

import com.teragrep.jai_02.entry.EntryAliasFactory;
import com.teragrep.jai_02.entry.EntryAliasString;
import com.teragrep.jai_02.password.DecodedHex;
import com.teragrep.jai_02.password.EncodedHex;
import com.teragrep.jai_02.password.PasswordEntry;
import com.teragrep.jai_02.password.PasswordEntryFactory;
import com.teragrep.jai_02.user.UserToAliasMapping;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Provides access to the KeyStore, such as loading, saving
 * and deleting entries. Keeps track of the username:alias mapping
 * via the UserToAliasMapping object.
 */
public class KeyStoreAccessImpl implements KeyStoreAccess {
    private final String keyStorePath;
    private final char[] keyStorePassword;
    private final EntryAliasFactory entryAliasFactory;
    private final UserToAliasMapping userToAliasMapping;
    private final KeyStore keyStore;

    public KeyStoreAccessImpl(final KeyStore keyStore, final String keyStorePath, final char[] keyStorePassword) {
        this(keyStore, keyStorePath, keyStorePassword, new EntryAliasFactory());
    }
    public KeyStoreAccessImpl(final KeyStore keyStore, final String keyStorePath, final char[] keyStorePassword, final EntryAliasFactory entryAliasFactory) {
        this.entryAliasFactory = entryAliasFactory;
        this.keyStorePassword = keyStorePassword;
        this.keyStorePath = keyStorePath;
        this.keyStore = keyStore;
        this.userToAliasMapping = new UserToAliasMapping(keyStore, this.entryAliasFactory.split());
    }

    public PasswordEntry loadKey(final String username) throws UnrecoverableEntryException, KeyStoreException, InvalidKeyException {
        if (!userToAliasMapping.has(username)) {
            throw new InvalidKeyException("Username <[" + username + "]> was not found in the map!");
        }
        final String alias = userToAliasMapping.get(username);

        PasswordEntryFactory keyWithSecret = new PasswordEntryFactory(
                new EntryAliasString(new DecodedHex(alias).decodeString(), entryAliasFactory.split()).toEntryAlias());

        final KeyStore.SecretKeyEntry ske;
        try {
             ske = (KeyStore.SecretKeyEntry) keyStore.getEntry(new EncodedHex(keyWithSecret.asEntryAlias().toString()).encode(),
                    new KeyStore.PasswordProtection(keyStorePassword));
        } catch (NoSuchAlgorithmException e) {
            // does not happen since algorithms are defined via enums
            throw new RuntimeException("Invalid algorithm provided for KeyStore", e);
        }

        if (ske == null) {
            throw new InvalidKeyException("Could not find SecretKey in KeyStore for username <[" + username + "]>");
        }

        return new PasswordEntry(
                keyWithSecret.asEntryAlias(),
                new SecretKeySpec(ske.getSecretKey().getEncoded(), keyWithSecret.keyAlgorithm().get().toString())
        );
    }

    public void saveKey(final String username, final char[] password) throws KeyStoreException {
        // Generate Key based on username and set keyStore password
        boolean aliasAlreadyExists = checkForExistingAlias(username);
        if (aliasAlreadyExists) {
            throw new IllegalArgumentException("Alias for username <[" + username + "]> already exists in KeyStore!");
        }

        PasswordEntryFactory keyWithSecret = new PasswordEntryFactory(entryAliasFactory.build(username));
        String encodedEntryAlias = new EncodedHex(keyWithSecret.asEntryAlias().toString()).encode();
        try {
            keyStore.setEntry(encodedEntryAlias, new KeyStore.SecretKeyEntry(keyWithSecret.build(password).secretKey()),
                    new KeyStore.PasswordProtection(keyStorePassword));
            OutputStream outputStream = Files.newOutputStream(Paths.get(keyStorePath));
            keyStore.store(outputStream, keyStorePassword);
            outputStream.close();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Invalid algorithm provided: ", e);
        } catch (CertificateException e) {
            throw new RuntimeException("Certificates could not be stored: ", e);
        } catch (IOException e) {
            throw new RuntimeException("I/O error storing keyStore: ", e);
        }

        // Put user->user:alias mapping and store keyStore in file
        userToAliasMapping.put(keyWithSecret.asEntryAlias().userName().toString(), encodedEntryAlias);
    }

    public boolean verifyKey(final String username, final char[] password) throws
            UnrecoverableEntryException, KeyStoreException, InvalidKeyException {
        // Get stored SecretKey and compare to newly generated key with same salt
        final PasswordEntry storedKeyPair = loadKey(username);
        final SecretKey newKey = new PasswordEntryFactory(entryAliasFactory.build(username, storedKeyPair.entryAlias().salt())).build(password).secretKey();
        return storedKeyPair.secretKey().equals(newKey);
    }

    public int deleteKey(final String usernameToRemove) throws KeyStoreException, IOException {
        final Enumeration<String> aliases = keyStore.aliases();
        final List<String> aliasesToRemove = new ArrayList<>();
        while (aliases.hasMoreElements()) {
            final String originalAlias = aliases.nextElement();
            final String decodedAlias = new DecodedHex(originalAlias).decodeString();
            final EntryAliasString entryAliasString = new EntryAliasString(decodedAlias, entryAliasFactory.split());

            final String username = entryAliasString.toEntryAlias().userName().toString();
            if (username.equals(usernameToRemove)) {
                aliasesToRemove.add(originalAlias);
            }
        }

        // remove entries from in-memory keyStore
        for (String alias : aliasesToRemove) {
            keyStore.deleteEntry(alias);
        }

        // commit changes to disk
        try {
            OutputStream outputStream = Files.newOutputStream(Paths.get(keyStorePath));
            keyStore.store(outputStream, keyStorePassword);
            outputStream.close();
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException("Error storing keyStore after alias deletion: ", e);
        }

        userToAliasMapping.remove(usernameToRemove);

        return aliasesToRemove.size();
    }

    public boolean checkForExistingAlias(final String usernameToCheck) throws KeyStoreException {
        boolean exists = false;

        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = new DecodedHex(aliases.nextElement()).decodeString();
            final EntryAliasString entryAliasString = new EntryAliasString(alias, entryAliasFactory.split());

            final String username = entryAliasString.toEntryAlias().userName().toString();
            if (username.equals(usernameToCheck)) {
                exists = true;
                break;
            }
        }

        return exists;
    }

    public String keyStorePath() {
        return keyStorePath;
    }

    public char[] keyStorePassword() {
        return keyStorePassword;
    }
}
