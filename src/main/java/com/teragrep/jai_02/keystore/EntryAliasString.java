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

import java.util.Base64;

/**
 * Provides facilities to generate an EntryAlias object from
 * a compliant String.
 */
public class EntryAliasString {

    private final String alias;
    private final Split split;

    public EntryAliasString(String alias, Split split) {
        this.alias = alias;
        this.split = split;
    }

    public EntryAlias toEntryAlias() {
        String[] fragments = split.asPattern().split(alias);
        if (fragments.length != 3) {
            throw new IllegalArgumentException("Invalid alias: " + alias + " does not decode into 3 parts with " + split);
        }

        String userName = fragments[0];
        UserNameValid userNameValid = new UserNameValid(new UserNameImpl(userName, split));
        Salt salt = new Salt(Base64.getDecoder().decode(fragments[1]));

        int iterationCount;
        try {
            iterationCount = Integer.parseInt(fragments[2]);
        } catch (NumberFormatException e) {
            throw new IllegalStateException("Invalid iterationCount was <[ " + fragments[2] + "]>, expected integer.");
        }



        return new EntryAlias(userNameValid, salt, iterationCount, split);
    }

    @Override
    public String toString() {
        return alias;
    }
}
