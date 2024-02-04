package com.dicectf2024.dictionaryservice

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log

class SignatureService : Service() {
    private val TAG: String = "dicectf:DictionaryService:SignatureService"

    override fun onCreate() {
        Log.d(TAG, "onCreate called")
        super.onCreate()
    }

    override fun onBind(intent: Intent): IBinder {
        Log.d(TAG, "onBind called")
        return binder
    }

    private val binder = object : ISignatureService.Stub() {
        override fun sign(data: String): String {
            return SignatureUtils.sign(data)
        }
    }
}