package com.dicectf2024.dictionaryservice

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature

object SignatureUtils {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "dictionary-intent-key"
    private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    fun createKeyIfNotExists() {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)

        if (keyStore.containsAlias(KEY_ALIAS)) {
            return
        }

        val keyPairGenerator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
        keyPairGenerator.initialize(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN
            ).setDigests(KeyProperties.DIGEST_SHA256).build()
        )
        keyPairGenerator.generateKeyPair()
    }

    fun sign(data: String): String {
        createKeyIfNotExists()

        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)
        val privateKeyEntry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initSign(privateKeyEntry.privateKey)
        signature.update(data.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(
            signature.sign(),
            Base64.NO_PADDING or Base64.NO_WRAP or Base64.URL_SAFE
        )
    }

    fun verify(data: String, signatureString: String): Boolean {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)
        val privateKeyEntry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        val publicKey = privateKeyEntry.certificate.publicKey
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initVerify(publicKey)
        signature.update(data.toByteArray(Charsets.UTF_8))
        return signature.verify(
            Base64.decode(
                signatureString,
                Base64.NO_PADDING or Base64.NO_WRAP or Base64.URL_SAFE
            )
        )
    }
}