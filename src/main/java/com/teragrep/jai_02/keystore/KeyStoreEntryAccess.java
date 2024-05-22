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

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

/**
 * Provides access to the entries in the KeyStore, such as
 * loading, saving and deleting. Stores the KeyStore to persistent
 * storage after each operation.
 */
public class KeyStoreEntryAccess {
    private final KeyStoreAccess ksa;
    public KeyStoreEntryAccess(KeyStoreAccess ksa) {
        this.ksa = ksa;
    }

    public SecretKeySpec fetchEntry(EntryAliasSecretKeyFactory entryAliasSecretKeyFactory) throws UnrecoverableEntryException, KeyStoreException {
        KeyStore.SecretKeyEntry ske;
        try {
            ske = (KeyStore.SecretKeyEntry) ksa.keyStore().getEntry(entryAliasSecretKeyFactory.asEntryAlias().toString(), new KeyStore.PasswordProtection(ksa.keyStorePassword()));
        } catch (NoSuchAlgorithmException e) {
            // shouldn't happen as algorithms are given as enums instead of strings
            throw new RuntimeException(e);
        }
        return new SecretKeySpec(ske.getSecretKey().getEncoded(), entryAliasSecretKeyFactory.keyAlgorithm().get().toString());
    }

    public void storeEntry(EntryAliasSecretKeyFactory entryAliasSecretKeyFactory, char[] password) throws KeyStoreException {
        try {
            ksa.keyStore().setEntry(entryAliasSecretKeyFactory.asEntryAlias().toString(), new KeyStore.SecretKeyEntry(entryAliasSecretKeyFactory.build(password)),
                    new KeyStore.PasswordProtection(ksa.keyStorePassword()));

            ksa.keyStore().store(Files.newOutputStream(Paths.get(ksa.keyStorePath())), ksa.keyStorePassword());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | CertificateException |
                 IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void deleteEntry(String alias) throws KeyStoreException, IOException {
        ksa.keyStore().deleteEntry(alias);
        try {
            ksa.keyStore().store(Files.newOutputStream(Paths.get(ksa.keyStorePath())), ksa.keyStorePassword());
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public Enumeration<String> aliases() throws KeyStoreException {
        return ksa.keyStore().aliases();
    }
}
