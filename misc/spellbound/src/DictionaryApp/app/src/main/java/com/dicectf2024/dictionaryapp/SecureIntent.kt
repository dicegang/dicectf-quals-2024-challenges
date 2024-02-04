package com.dicectf2024.dictionaryapp

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle

object SecureIntent {
    private val CALLER_IDENTITY_TAG: String = "__ci"
    private val TIMESTAMP_TAG: String = "__t"

    // some intentionally garbage values so that the PendingIntent cannot be launched
    private val FAKE_PACKAGE_NAME = "com.fake.package"

    private fun getRandomString(length: Int): String {
        val allowedChars = ('A'..'Z') + ('a'..'z') + ('0'..'9')
        return (1..length)
            .map { allowedChars.random() }
            .joinToString("")
    }

    fun make(context: Context, intent: Intent): Intent {
        intent.setExtrasClassLoader(context.classLoader)
        val extras: Bundle = intent.extras ?: Bundle()
        extras.classLoader = context.classLoader

        // the component name is intentionally garbage so this intent never gets launched
        // we use a PendingIntent for identity because the creator package name and UID is
        // set by the system, meaning it cannot be spoofed. see
        // https://android.googlesource.com/platform/frameworks/base/+/HEAD/core/java/android/app/PendingIntent.java#1129
        // and then we can verify on the receiving side that caller is trusted
        val identityIntent =
            Intent().setComponent(ComponentName(context, FAKE_PACKAGE_NAME + getRandomString(6)))
        val identity: PendingIntent = PendingIntent.getActivity(
            context,
            0,
            identityIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_ONE_SHOT
        )
        extras.putParcelable(CALLER_IDENTITY_TAG, identity)
        extras.putLong(TIMESTAMP_TAG, System.currentTimeMillis())
        intent.putExtras(extras)

        return intent
    }
}