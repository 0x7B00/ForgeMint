package com.dere3046.forgemint

import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.security.keystore.IKeystoreService

class KeystoreInterceptor(
    private val ksBinder: IBinder,
    private val backdoor: IBinder,
) : BinderInterceptor() {

    private val transactionCodes: Map<Int, String> by lazy {
        mutableMapOf<Int, String>().apply {
            IKeystoreService.Stub::class.java.declaredFields.filter {
                it.type == Int::class.javaPrimitiveType && it.name.startsWith("TRANSACTION_")
            }.forEach { f ->
                f.isAccessible = true
                put(f.getInt(null), f.name.removePrefix("TRANSACTION_"))
            }
        }
    }

    private val attestKeyCode: Int? by lazy {
        try {
            IKeystoreService.Stub::class.java
                .getDeclaredField("TRANSACTION_attestKey")
                .apply { isAccessible = true }
                .getInt(null)
        } catch (_: Exception) { null }
    }

    override fun onPreTransact(
        txId: Long, target: IBinder, code: Int, flags: Int,
        callingUid: Int, callingPid: Int, data: Parcel,
    ): TransactionResult {
        if (ConfigManager.shouldSkip(callingUid)) {
            return TransactionResult.ContinueAndSkipPost
        }

        val txnName = transactionCodes[code] ?: "0x${code.toString(16)}"
        Logger.d("K1 preTr: $txnName uid=$callingUid")

        if (code == attestKeyCode && ConfigManager.shouldGenerate(callingUid)) {
            Logger.i("K1 attestKey uid=$callingUid (software gen)")
        }

        return TransactionResult.Continue
    }

    override fun onPostTransact(
        txId: Long, target: IBinder, code: Int, flags: Int,
        callingUid: Int, callingPid: Int, data: Parcel,
        reply: Parcel?, resultCode: Int,
    ): TransactionResult {
        if (resultCode != 0 || reply == null) return TransactionResult.Skip
        if (ConfigManager.shouldSkip(callingUid)) return TransactionResult.Skip

        val txnName = transactionCodes[code] ?: "0x${code.toString(16)}"
        Logger.d("K1 postTr: $txnName uid=$callingUid")

        return TransactionResult.Skip
    }

    companion object {
        fun isCompatible(): Boolean =
            Build.VERSION.SDK_INT in Build.VERSION_CODES.Q..Build.VERSION_CODES.R
    }
}
