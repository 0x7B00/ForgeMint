/*
 * Copyright (C) 2026  TheGeniusClub
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <https://www.gnu.org/licenses/>.
 */

package android.security.keystore;

import android.os.IBinder;
import android.os.RemoteException;
import android.security.keymaster.KeyCharacteristics;

public interface IKeystoreKeyCharacteristicsCallback {
    void onFinished(KeystoreResponse response, KeyCharacteristics characteristics) throws RemoteException;

    abstract class Stub {
        public static IKeystoreKeyCharacteristicsCallback asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
