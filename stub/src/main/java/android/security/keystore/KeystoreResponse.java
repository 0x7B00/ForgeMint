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

import android.os.Parcel;
import android.os.Parcelable;

public class KeystoreResponse implements Parcelable {
    public final int error_code_;
    public final String error_msg_;

    protected KeystoreResponse(int errorCode, String errorMsg) {
        error_code_ = errorCode;
        error_msg_ = errorMsg;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<KeystoreResponse> CREATOR = new Creator<KeystoreResponse>() {
        @Override
        public KeystoreResponse createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }
        @Override
        public KeystoreResponse[] newArray(int size) {
            return new KeystoreResponse[size];
        }
    };
}
