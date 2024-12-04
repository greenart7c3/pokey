package com.koalasat.pokey.models

import android.content.Context
import android.content.SharedPreferences
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object PrefKeys {
    const val NOSTR_BROADCAST = "broadcast"
    const val EXTERNAL_SIGNER = "external_signer"
    const val INBOX_PUBKEY = "inbox_pubkey"
}
object DefaultKeys {
    const val BROADCAST = true
    const val EXTERNAL_SIGNER = "com.greenart7c3.nostrsigner"
}

object EncryptedStorage {
    private const val PREFERENCES_NAME = "secret_keeper"

    private lateinit var sharedPreferences: SharedPreferences

    private val _inboxPubKey = MutableLiveData<String>()
    val inboxPubKey: LiveData<String> get() = _inboxPubKey

    private val _broadcast = MutableLiveData<Boolean>().apply { DefaultKeys.BROADCAST }
    val broadcast: LiveData<Boolean> get() = _broadcast

    private val _externalSigner = MutableLiveData<String>().apply { DefaultKeys.EXTERNAL_SIGNER }
    val externalSigner: LiveData<String> get() = _externalSigner

    fun init(context: Context) {
        val masterKey: MasterKey =
            MasterKey.Builder(context, MasterKey.DEFAULT_MASTER_KEY_ALIAS)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

        sharedPreferences = EncryptedSharedPreferences.create(
            context,
            PREFERENCES_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        ) as EncryptedSharedPreferences

        _broadcast.postValue(sharedPreferences.getBoolean(PrefKeys.NOSTR_BROADCAST, DefaultKeys.BROADCAST))
        _externalSigner.postValue(sharedPreferences.getString(PrefKeys.EXTERNAL_SIGNER, DefaultKeys.EXTERNAL_SIGNER) ?: DefaultKeys.EXTERNAL_SIGNER)
        _inboxPubKey.postValue(sharedPreferences.getString(PrefKeys.INBOX_PUBKEY, ""))
    }

    fun updateExternalSigner(newValue: String) {
        sharedPreferences.edit().putString(PrefKeys.EXTERNAL_SIGNER, newValue).apply()
        _externalSigner.postValue(newValue)
    }

    fun updateBroadcast(newValue: Boolean) {
        sharedPreferences.edit().putBoolean(PrefKeys.NOSTR_BROADCAST, newValue).apply()
        _broadcast.postValue(newValue)
    }

    fun updateInboxPubKey(pubKey: String) {
        sharedPreferences.edit().putString(PrefKeys.INBOX_PUBKEY, pubKey).apply()
        _inboxPubKey.postValue(pubKey)
    }
}
