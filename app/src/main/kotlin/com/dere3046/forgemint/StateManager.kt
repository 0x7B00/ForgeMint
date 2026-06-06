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

package com.dere3046.forgemint

import android.os.IBinder
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyMetadata
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

object StateManager {

    data class KeyIdentifier(val uid: Int, val alias: String)

    data class KeyEntry(
        val uid: Int,
        val alias: String,
        val nspace: Long,
        val metadata: KeyMetadata,
        val keyPair: KeyPair,
        val securityLevel: Int,
        val securityLevelBinder: IKeystoreSecurityLevel?,
        val certChain: List<X509Certificate>,
    )

    private val cache = ConcurrentHashMap<String, KeyEntry>()
    private val patchedChains = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()
    private val opCounters = ConcurrentHashMap<Int, java.util.concurrent.atomic.AtomicInteger>()

    private const val MAX_OPS_PER_UID = 15

    fun acquireOp(uid: Int): Boolean {
        val counter = opCounters.getOrPut(uid) { java.util.concurrent.atomic.AtomicInteger(0) }
        if (counter.incrementAndGet() > MAX_OPS_PER_UID) {
            counter.decrementAndGet()
            Logger.w("LRU: UID=$uid op limit ($MAX_OPS_PER_UID) reached")
            return false
        }
        return true
    }

    fun releaseOp(uid: Int) {
        opCounters[uid]?.decrementAndGet()
    }

    fun store(entry: KeyEntry) {
        cache[key(entry.uid, entry.alias)] = entry
        GeneratedKeyPersistence.store(entry)
    }

    fun lookup(uid: Int, alias: String): KeyEntry? = cache[key(uid, alias)]

    fun lookupByNspace(uid: Int, nspace: Long): KeyEntry? {
        return cache.values.find { it.uid == uid && it.nspace == nspace }
    }

    fun remove(uid: Int, alias: String) {
        cache.remove(key(uid, alias))
        patchedChains.remove(KeyIdentifier(uid, alias))
        GeneratedKeyPersistence.remove(uid, alias)
    }

    private var keysLoaded = false

    fun loadPersistedKeys(ksService: android.system.keystore2.IKeystoreService) {
        if (keysLoaded) return
        keysLoaded = true
        var count = 0
        for (lk in GeneratedKeyPersistence.loadAll()) {
            if (lk.metadata == null) continue
            val binder = try {
                ksService.getSecurityLevel(lk.securityLevel)
            } catch (_: Exception) { null }
            store(KeyEntry(
                uid = lk.uid,
                alias = lk.alias,
                nspace = lk.nspace,
                metadata = lk.metadata,
                keyPair = lk.keyPair,
                securityLevel = lk.securityLevel,
                securityLevelBinder = binder,
                certChain = lk.certChain,
            ))
            count++
        }
        if (count > 0) Logger.i("Loaded $count persisted keys")
    }

    fun listForUid(uid: Int): List<KeyEntry> {
        return cache.values.filter { it.uid == uid }
    }

    fun getPatchedChain(keyId: KeyIdentifier): Array<Certificate>? = patchedChains[keyId]

    fun cachePatchedChain(keyId: KeyIdentifier, chain: Array<Certificate>) {
        patchedChains[keyId] = chain
    }

    fun clearAll() {
        val count = cache.size
        cache.clear()
        patchedChains.clear()
        opCounters.clear()
        Logger.i("Cleared all state ($count entries)")
    }

    private fun key(uid: Int, alias: String) = "$uid:$alias"
}
