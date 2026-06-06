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

package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

public class KeyCharacteristics implements Parcelable {
    public KeymasterArguments swEnforced = new KeymasterArguments();
    public KeymasterArguments hwEnforced = new KeymasterArguments();

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<KeyCharacteristics> CREATOR = new Creator<KeyCharacteristics>() {
        @Override
        public KeyCharacteristics createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }
        @Override
        public KeyCharacteristics[] newArray(int size) {
            return new KeyCharacteristics[size];
        }
    };
}
