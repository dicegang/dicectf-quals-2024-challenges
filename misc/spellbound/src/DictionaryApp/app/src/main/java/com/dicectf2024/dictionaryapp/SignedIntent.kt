package com.dicectf2024.dictionaryapp

import android.content.Context
import android.content.Intent
import android.os.Bundle
import org.json.JSONObject
import com.dicectf2024.dictionaryservice.ISignatureService

object SignedIntent {
    private const val CALLER_IDENTITY_TAG: String = "__ci"
    private const val CALLER_IDENTITY_SIGNATURE: String = "__s"

    fun make(context: Context, intent: Intent, signatureService: ISignatureService): Intent {
        val extras: Bundle = intent.extras ?: Bundle()

        val jsonIdentity = JSONObject()
        jsonIdentity.put("packageName", context.packageName)
        jsonIdentity.put("timestamp", System.currentTimeMillis())

        val identity = jsonIdentity.toString()
        val signature = signatureService.sign(identity)

        extras.putString(CALLER_IDENTITY_TAG, identity)
        extras.putString(CALLER_IDENTITY_SIGNATURE, signature)

        intent.putExtras(extras)
        return intent
    }
}