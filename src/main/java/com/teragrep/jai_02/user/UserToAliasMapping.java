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
package com.teragrep.jai_02.user;

import com.teragrep.jai_02.entry.EntryAlias;
import com.teragrep.jai_02.entry.EntryAliasString;
import com.teragrep.jai_02.entry.Split;
import com.teragrep.jai_02.password.DecodedHex;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * Map between the username and EntryAlias.
 * Loads existing aliases from the KeyStore on object initialization.
 * If there are multiple aliases for one username, the last one encountered takes priority.
 */
public class UserToAliasMapping {
    private final Map<String, String> internalMap;
    public UserToAliasMapping(KeyStore ks, Split split) {
        this.internalMap = new HashMap<>();

        // Initialize map with existing contents
        final Enumeration<String> aliases;
        try {
            aliases = ks.aliases();
        } catch (KeyStoreException e) {
            throw new RuntimeException("KeyStore was not initialized, " +
                    "cannot initialize userToAliasMapping!");
        }

        while (aliases.hasMoreElements()) {
            final String originalAlias = aliases.nextElement();
            final EntryAlias k = new EntryAliasString(originalAlias, split).toEntryAlias();

            this.internalMap.put(new DecodedHex(k.userName().toString()).decodeString(), originalAlias);
        }
    }

    public void put(String username, String fullAlias) {
        this.internalMap.put(username, fullAlias);
    }

    public String get(String username) {
        return this.internalMap.get(username);
    }

    public boolean has(String username) {
        return this.internalMap.containsKey(username);
    }

    public void remove(String username) {
        this.internalMap.remove(username);
    }
}
