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

public class KeyStoreEntryAccess {
    private final KeyStoreFactory keyStoreFactory;
    public KeyStoreEntryAccess(KeyStoreFactory ksf) {
        this.keyStoreFactory = ksf;
    }

    public SecretKeySpec fetchEntry(EntryAliasWithSecretKey entryAliasWithSecretKey) throws UnrecoverableEntryException, KeyStoreException {
        KeyStore.SecretKeyEntry ske;
        try {
            ske = (KeyStore.SecretKeyEntry) keyStoreFactory.build().getEntry(entryAliasWithSecretKey.asEntryAlias().toString(), new KeyStore.PasswordProtection(keyStoreFactory.password()));
        } catch (NoSuchAlgorithmException e) {
            // shouldn't happen as algorithms are given as enums instead of strings
            throw new RuntimeException(e);
        }
        return new SecretKeySpec(ske.getSecretKey().getEncoded(), entryAliasWithSecretKey.keyAlgorithm().get().toString());
    }

    public void storeEntry(EntryAliasWithSecretKey entryAliasWithSecretKey, char[] password) throws KeyStoreException {
        KeyStore ks = keyStoreFactory.build();
        try {
            ks.setEntry(entryAliasWithSecretKey.asEntryAlias().toString(), new KeyStore.SecretKeyEntry(entryAliasWithSecretKey.asSecretKey(password)),
                    new KeyStore.PasswordProtection(keyStoreFactory.password()));

            ks.store(Files.newOutputStream(Paths.get(keyStoreFactory.path())), keyStoreFactory.password());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | CertificateException |
                 IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void deleteEntry(String alias) throws KeyStoreException, IOException {
        KeyStore ks = keyStoreFactory.build();
        ks.deleteEntry(alias);
        try {
            ks.store(Files.newOutputStream(Paths.get(keyStoreFactory.path())), keyStoreFactory.password());
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}
