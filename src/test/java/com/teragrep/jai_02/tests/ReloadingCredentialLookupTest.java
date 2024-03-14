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

package com.teragrep.jai_02.tests;

import com.teragrep.jai_02.ICredentialLookup;
import com.teragrep.jai_02.ReloadingCredentialLookup;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class ReloadingCredentialLookupTest {

    @Test()
    public void readTest() {
        ICredentialLookup credentialLookup = new ReloadingCredentialLookup("src/test/resources/credentials.json", 5);
        Assertions.assertEquals("XOsAqIhmKUTwWMjWwDaYmVgR8sl_l70H1oDPBw9z2yY",
                credentialLookup.getCredential("trusted-12"));
    }

    @Test()
    public void readNoSuchTest() {
        ICredentialLookup credentialLookup = new ReloadingCredentialLookup("src/test/resources/credentials.json",5);
        Assertions.assertNull(credentialLookup.getCredential("trusted-00"));
    }

    @Test()
    public void reloadTest() throws IOException, InterruptedException {
        final String originalCredentials = "[{\"identity\": \"trusted-12\", \"credential\": \"XOsAqIhmKUTwWMjWwDaYmVgR8sl_l70H1oDPBw9z2yY\"}]\n";
        final String changedCredentials = "[{\"identity\": \"trusted-12\", \"credential\": \"differentPass\"}]\n";

        final String testFile = "target/credentials.reload.json";

        try(BufferedWriter writer = new BufferedWriter(new FileWriter(testFile))) {
            writer.write(originalCredentials);
        }

        ICredentialLookup credentialLookup = new ReloadingCredentialLookup(testFile,1);

        Assertions.assertEquals("XOsAqIhmKUTwWMjWwDaYmVgR8sl_l70H1oDPBw9z2yY",
                credentialLookup.getCredential("trusted-12"));

        try(BufferedWriter writer = new BufferedWriter(new FileWriter(testFile))) {
            writer.write(changedCredentials);
        }

        Thread.sleep(2000);

        Assertions.assertEquals("differentPass",
                credentialLookup.getCredential("trusted-12"));
    }
}

