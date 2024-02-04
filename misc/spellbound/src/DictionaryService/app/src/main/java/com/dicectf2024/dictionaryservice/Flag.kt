package com.dicectf2024.dictionaryservice

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object Flag {
    private const val TAG: String = "dicectf:DictionaryService:Flag"

    const val MAGIC_WORD = "flag"

    private fun getRandomString(length: Int) : String {
        val allowedChars = ('A'..'Z') + ('a'..'z') + ('0'..'9')
        return (1..length)
            .map { allowedChars.random() }
            .joinToString("")
    }

    fun get(context: Context): String {
        val masterKey: MasterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        val sharedPreferences: SharedPreferences = EncryptedSharedPreferences.create(
            context,
            "secret_preferences",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        if (!sharedPreferences.contains(MAGIC_WORD)) {
            val flagToken = getRandomString(16)
            sharedPreferences.edit().putString(MAGIC_WORD, flagToken).apply()
        }

        val flagToken = sharedPreferences.getString(MAGIC_WORD, "")!!
        Log.d(TAG, "Flag token: $flagToken")
        return flagToken
    }
}