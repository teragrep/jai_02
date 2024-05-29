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
package com.teragrep.jai_02.password;

import com.teragrep.jai_02.entry.EntryAlias;
import com.teragrep.jai_02.entry.KeyAlgorithm;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Builds a SecretKey for an EntryAlias using the
 * given algorithm.
 */
public class PasswordEntryFactory {
    private final EntryAlias entryAlias;
    private final KeyAlgorithm keyAlgorithm;

    public PasswordEntryFactory(final EntryAlias entryAlias) {
        this(entryAlias, new KeyAlgorithm());
    }

    public PasswordEntryFactory(final EntryAlias entryAlias, final KeyAlgorithm keyAlgorithm) {
        this.entryAlias = entryAlias;
        this.keyAlgorithm = keyAlgorithm;
    }

    public PasswordEntry build(final char[] password)  {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, entryAlias.salt().asBytes(), entryAlias.iterationCount(), 160);
        final SecretKeyFactory secretKeyFactory;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance(keyAlgorithm.get().toString());
        } catch (NoSuchAlgorithmException e) {
            // Should not happen as the algorithms are defined as known-good enums
            throw new RuntimeException(e);
        }

        final SecretKey secretKey;
        try {
             secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Given key specification was inappropriate for "
                    + keyAlgorithm.get().toString() + " algorithm\n", e);
        }

        return new PasswordEntry(
                entryAlias,
                secretKey);
    }

    public KeyAlgorithm keyAlgorithm() {
        return this.keyAlgorithm;
    }

    public EntryAlias asEntryAlias() {
        return this.entryAlias;
    }
}
