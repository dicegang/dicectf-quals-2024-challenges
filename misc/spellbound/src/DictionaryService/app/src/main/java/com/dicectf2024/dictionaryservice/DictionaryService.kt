package com.dicectf2024.dictionaryservice

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.IBinder
import android.util.Log
import org.json.JSONArray
import java.io.IOException
import java.nio.charset.Charset


class DictionaryService : Service() {
    private val TAG: String = "dicectf:DictionaryService:DictionaryService"

    override fun onCreate() {
        Log.d(TAG, "onCreate called")
        super.onCreate()
    }

    override fun onBind(intent: Intent): IBinder? {
        Log.d(TAG, "onBind called, intent=$intent")
        if (IntentChecker.isSecure(applicationContext, intent)) {
            return binder
        }

        Log.d(TAG, "Security check failed! :(")
        return null
    }

    private fun loadDictionary(): JSONArray? {
        try {
            val inputStream = assets.open("dictionary.json")
            val size = inputStream.available()
            val buffer = ByteArray(size)
            inputStream.read(buffer)
            inputStream.close()
            val json = String(buffer, Charset.forName("UTF-8"))
            return JSONArray(json)
        } catch (e: IOException) {
            e.printStackTrace()
        }
        return null
    }

    fun findEntryForWord(targetWord: String): String? {
        if (targetWord == Flag.MAGIC_WORD) {
            return Flag.get(this)
        }

        val dictionary = loadDictionary() ?: return null

        for (i in 0 until dictionary.length()) {
            val entry = dictionary.getJSONObject(i)
            val word = entry.optString("word")

            if (word == targetWord) {
                return entry.toString()
            }
        }

        return null
    }


    private val binder = object : IDictionaryService.Stub() {
        override fun getData(word: String): String {
            val entry = findEntryForWord(word)
            return entry ?: ""
        }
    }
}