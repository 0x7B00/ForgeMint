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

public class KeymasterDefs {

    // Tag type masks
    public static final int KM_INVALID = 0 << 28;
    public static final int KM_ENUM = 1 << 28;
    public static final int KM_ENUM_REP = 2 << 28;
    public static final int KM_UINT = 3 << 28;
    public static final int KM_UINT_REP = 4 << 28;
    public static final int KM_ULONG = 5 << 28;
    public static final int KM_DATE = 6 << 28;
    public static final int KM_BOOL = 7 << 28;
    public static final int KM_BIGNUM = 8 << 28;
    public static final int KM_BYTES = 9 << 28;
    public static final int KM_ULONG_REP = 10 << 28;

    // Tags
    public static final int KM_TAG_INVALID = KM_INVALID | 0;
    public static final int KM_TAG_PURPOSE = KM_ENUM_REP | 1;
    public static final int KM_TAG_ALGORITHM = KM_ENUM | 2;
    public static final int KM_TAG_KEY_SIZE = KM_UINT | 3;
    public static final int KM_TAG_BLOCK_MODE = KM_ENUM_REP | 4;
    public static final int KM_TAG_DIGEST = KM_ENUM_REP | 5;
    public static final int KM_TAG_PADDING = KM_ENUM_REP | 6;
    public static final int KM_TAG_CALLER_NONCE = KM_BOOL | 7;
    public static final int KM_TAG_MIN_MAC_LENGTH = KM_UINT | 8;

    public static final int KM_TAG_EC_CURVE = KM_ENUM | 10;

    public static final int KM_TAG_RSA_PUBLIC_EXPONENT = KM_ULONG | 200;
    public static final int KM_TAG_INCLUDE_UNIQUE_ID = KM_BOOL | 202;
    public static final int KM_TAG_RSA_OAEP_MGF_DIGEST = KM_ENUM_REP | 203;

    public static final int KM_TAG_BOOTLOADER_ONLY = KM_BOOL | 301;
    public static final int KM_TAG_ROLLBACK_RESISTANCE = KM_BOOL | 303;
    public static final int KM_TAG_EARLY_BOOT_ONLY = KM_BOOL | 305;

    public static final int KM_TAG_ACTIVE_DATETIME = KM_DATE | 400;
    public static final int KM_TAG_ORIGINATION_EXPIRE_DATETIME = KM_DATE | 401;
    public static final int KM_TAG_USAGE_EXPIRE_DATETIME = KM_DATE | 402;
    public static final int KM_TAG_MIN_SECONDS_BETWEEN_OPS = KM_UINT | 403;
    public static final int KM_TAG_MAX_USES_PER_BOOT = KM_UINT | 404;

    public static final int KM_TAG_USER_ID = KM_UINT | 501;
    public static final int KM_TAG_USER_SECURE_ID = KM_ULONG_REP | 502;
    public static final int KM_TAG_NO_AUTH_REQUIRED = KM_BOOL | 503;
    public static final int KM_TAG_USER_AUTH_TYPE = KM_ENUM | 504;
    public static final int KM_TAG_AUTH_TIMEOUT = KM_UINT | 505;
    public static final int KM_TAG_ALLOW_WHILE_ON_BODY = KM_BOOL | 506;
    public static final int KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = KM_BOOL | 507;
    public static final int KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = KM_BOOL | 508;
    public static final int KM_TAG_UNLOCKED_DEVICE_REQUIRED = KM_BOOL | 509;
    public static final int KM_TAG_ALL_APPLICATIONS = KM_BOOL | 600;
    public static final int KM_TAG_APPLICATION_ID = KM_BYTES | 601;
    public static final int KM_TAG_CREATION_DATETIME = KM_DATE | 701;
    public static final int KM_TAG_ORIGIN = KM_ENUM | 702;
    public static final int KM_TAG_ROOT_OF_TRUST = KM_BYTES | 704;
    public static final int KM_TAG_OS_VERSION = KM_UINT | 705;
    public static final int KM_TAG_OS_PATCHLEVEL = KM_UINT | 706;
    public static final int KM_TAG_UNIQUE_ID = KM_BYTES | 707;
    public static final int KM_TAG_ATTESTATION_CHALLENGE = KM_BYTES | 708;
    public static final int KM_TAG_ATTESTATION_APPLICATION_ID = KM_BYTES | 709;
    public static final int KM_TAG_ATTESTATION_ID_BRAND = KM_BYTES | 710;
    public static final int KM_TAG_ATTESTATION_ID_DEVICE = KM_BYTES | 711;
    public static final int KM_TAG_ATTESTATION_ID_PRODUCT = KM_BYTES | 712;
    public static final int KM_TAG_ATTESTATION_ID_SERIAL = KM_BYTES | 713;
    public static final int KM_TAG_ATTESTATION_ID_IMEI = KM_BYTES | 714;
    public static final int KM_TAG_ATTESTATION_ID_MEID = KM_BYTES | 715;
    public static final int KM_TAG_ATTESTATION_ID_MANUFACTURER = KM_BYTES | 716;
    public static final int KM_TAG_ATTESTATION_ID_MODEL = KM_BYTES | 717;
    public static final int KM_TAG_VENDOR_PATCHLEVEL = KM_UINT | 718;
    public static final int KM_TAG_BOOT_PATCHLEVEL = KM_UINT | 719;
    public static final int KM_TAG_DEVICE_UNIQUE_ATTESTATION = KM_BOOL | 720;
    public static final int KM_TAG_IDENTITY_CREDENTIAL_KEY = KM_BOOL | 721;
    public static final int KM_TAG_STORAGE_KEY = KM_BOOL | 722;
    public static final int KM_TAG_ATTESTATION_ID_SECOND_IMEI = KM_BYTES | 723;

    // Algorithms
    public static final int KM_ALGORITHM_RSA = 1;
    public static final int KM_ALGORITHM_EC = 3;
    public static final int KM_ALGORITHM_AES = 32;
    public static final int KM_ALGORITHM_TRIPLE_DES = 33;
    public static final int KM_ALGORITHM_HMAC = 128;

    // Digest
    public static final int KM_DIGEST_NONE = 0;
    public static final int KM_DIGEST_MD5 = 1;
    public static final int KM_DIGEST_SHA1 = 2;
    public static final int KM_DIGEST_SHA_2_224 = 3;
    public static final int KM_DIGEST_SHA_2_256 = 4;
    public static final int KM_DIGEST_SHA_2_384 = 5;
    public static final int KM_DIGEST_SHA_2_512 = 6;

    // Padding
    public static final int KM_PAD_NONE = 1;
    public static final int KM_PAD_RSA_OAEP = 2;
    public static final int KM_PAD_RSA_PSS = 3;
    public static final int KM_PAD_RSA_PKCS1_1_5_ENCRYPT = 4;
    public static final int KM_PAD_RSA_PKCS1_1_5_SIGN = 5;
    public static final int KM_PAD_PKCS7 = 64;

    // Origin
    public static final int KM_ORIGIN_GENERATED = 0;
    public static final int KM_ORIGIN_IMPORTED = 2;
    public static final int KM_ORIGIN_UNKNOWN = 3;

    // Purpose
    public static final int KM_PURPOSE_ENCRYPT = 0;
    public static final int KM_PURPOSE_DECRYPT = 1;
    public static final int KM_PURPOSE_SIGN = 2;
    public static final int KM_PURPOSE_VERIFY = 3;
    public static final int KM_PURPOSE_ATTEST_KEY = 16;

    // Key formats
    public static final int KM_KEY_FORMAT_X509 = 0;
    public static final int KM_KEY_FORMAT_PKCS8 = 1;
    public static final int KM_KEY_FORMAT_RAW = 3;

    // Blob types
    public static final int KM_BLOB_STANDALONE = 0;
    public static final int KM_BLOB_REQUIRES_FILE_SYSTEM = 1;

    // Error codes
    public static final int KM_ERROR_OK = 0;
}
