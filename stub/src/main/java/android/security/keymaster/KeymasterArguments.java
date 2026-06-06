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

public class KeymasterArguments implements Parcelable {
    public void addEnum(int tag, int value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getEnum(int tag, int defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    public java.util.List<Integer> getEnums(int tag) {
        throw new UnsupportedOperationException("STUB!");
    }

    public byte[] getBytes(int tag, byte[] defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    public long getUnsignedInt(int tag, long defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    public java.util.Date getDate(int tag, java.util.Date defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    public void readFromParcel(Parcel in) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<KeymasterArguments> CREATOR = new Creator<KeymasterArguments>() {
        @Override
        public KeymasterArguments createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }
        @Override
        public KeymasterArguments[] newArray(int size) {
            return new KeymasterArguments[size];
        }
    };
}
