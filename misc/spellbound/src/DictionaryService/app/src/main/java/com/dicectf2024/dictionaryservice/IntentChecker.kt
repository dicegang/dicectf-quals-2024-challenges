package com.dicectf2024.dictionaryservice

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.util.Base64
import android.util.Log
import org.json.JSONObject


object IntentChecker {
    private const val TAG: String = "dicectf:DictionaryService:IntentChecker"

    private const val CALLER_IDENTITY_TAG: String = "__ci"
    private const val CALLER_IDENTITY_SIGNATURE: String = "__s"
    private const val CALLER_IDENTITY_TIMEOUT: Long = 10000


    // signature and package name of DictionaryApp
    private val TRUSTED_PACKAGE_NAME: String = "com.dicectf2024.dictionaryapp"

    // see https://developer.android.com/studio/publish/app-signing
    private val TRUSTED_SIGNATURE_HASH: String =
        "MIICxDCCAawCAQEwDQYJKoZIhvcNAQELBQAwKDETMBEGA1UEAwwKSm9obiBTbWl0aDERMA8GA1UECwwIRGljZUdhbmcwHhcNMjQwMTIyMjE1NzAzWhcNNDkwMTE1MjE1NzAzWjAoMRMwEQYDVQQDDApKb2huIFNtaXRoMREwDwYDVQQLDAhEaWNlR2FuZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMqJjRJOro8apjIWTLMAReeyYAKkzoblGCamR5TdL4y9xPNfY6RGjeSV4pd3v0-LGwwIj877W-eXdmmq4lImR83HWA8U3SO7QiaHR2E2ahy-cyMJDB0YAYWKICcLP9tm7yLOpTAV6l1w_BmDiOf5zmBTLT1W_41HOfKE8MH4j1WG7zp6la6fLbmGAlZ2JD33PCvaLKEYka7l8DcjMpWvyLkMUVNbjBvV8yrJu7TUgCWnEWGP6g2iEW2K8fYtFaemdAMZHmjGw0iIJLkVjpYziKqgs3-eNgF3o12gjwocjxIIaKy5qOi4x-Gtzl5J9GYusiAtEPTJtxaZCWeog7ABUFsCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEArAog02e-mM140AGj-s1EKK8EDHmHRZcMUTUfW3wVB4Ek-twTE-oaLg8FhrF98_91aDZ7Ab3Nz1CRn5WGDiY6J-_XS9N54AGYmi-fgeG7YXDz9Ju6r_qn4_FzTGeA1cEZBU5wPOW82ICnt5DbS-J11Re32QpvEPTTaMaMyVoFU1So07_fnEleKiIrhh6HvyVQyZwAfgVscN-mpqRCCXGeO12pB340QQ_9IldnlrCY6kebXp8pDPDW9eHcDNlsgt_ZVOM5k8JGqQw8UHLAJxDbRhxKPBqM_lfCqx1sASmuYKL9t-5742L_0yUY2NtLMHiFFir20tKn4foj9VDzcwm9Uw"

    fun isSecure(context: Context, intent: Intent): Boolean {
        // check intent identity exists
        val identity = intent.getStringExtra(CALLER_IDENTITY_TAG)
        val signatureString = intent.getStringExtra(CALLER_IDENTITY_SIGNATURE)
        if (identity == null || signatureString == null) {
            Log.d(TAG, "error - no identity exists")
            return false;
        }

        // check that the data matches the signature
        if (!SignatureUtils.verify(identity, signatureString)) {
            Log.d(TAG, "error - signature check failed")
            return false;
        }

        // check we have all required fields in the intent identity
        val jsonIdentity = JSONObject(identity)
        val callerPackageName = jsonIdentity.optString("packageName")
        val timestamp = jsonIdentity.optLong("timestamp")
        if (callerPackageName == "" || timestamp == 0L) {
            Log.d(TAG, "error - identity missing required fields")
            return false;
        }

        // check the package name matches what we expect
        if (callerPackageName != TRUSTED_PACKAGE_NAME) {
            Log.d(TAG, "error - caller package name mismatch")
            return false;
        }

        // check the identity hasn't expired
        Log.d(TAG, "caller identity: packageName=$callerPackageName, timestamp=$timestamp")
        if (System.currentTimeMillis() - timestamp > CALLER_IDENTITY_TIMEOUT) {
            Log.d(TAG, "error - identity with timestamp $timestamp has expired")
            return false;
        }

        // query PackageManager and verify there is only one app on the system with the
        // ability to bind to the signing service
        val packageManager: PackageManager = context.packageManager
        val allPackages = packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        val packagesWithPermission = ArrayList<String>()
        for (packageInfo in allPackages) {
            if (PackageManager.PERMISSION_GRANTED == packageManager.checkPermission(
                    "com.dicectf2024.permission.dictionary.BIND_SIGNATURE_SERVICE",
                    packageInfo.packageName
                )) {
                packagesWithPermission.add(packageInfo.applicationInfo.packageName)
            }
        }
        if (packagesWithPermission.size != 1 || packagesWithPermission[0] != callerPackageName) {
            Log.d(TAG, "error - only DictionaryApp should have the BIND_SIGNATURE_SERVICE permission")
            return false;
        }

        // query PackageManager for the package that corresponds to the sender
        val packageInfo: PackageInfo =
            packageManager.getPackageInfo(callerPackageName, PackageManager.GET_SIGNATURES)
        val signatures = packageInfo.signatures
        Log.d(TAG, "signatures: $signatures")
        if (signatures.size != 1) {
            Log.d(TAG, "error - caller package signed with multiple signatures")
            return false
        }
        val signature: android.content.pm.Signature = signatures[0]

        // verify that the signature of the installed app with the UID that created the PI
        // is indeed the same as our trusted app
        val signatureHash = Base64.encodeToString(
            signature.toByteArray(),
            Base64.NO_PADDING or Base64.NO_WRAP or Base64.URL_SAFE
        );
        Log.d(TAG, "signatureHash: $signatureHash")

        val isTrusted = TRUSTED_SIGNATURE_HASH == signatureHash
        if (!isTrusted) {
            Log.d(TAG, "error - caller signature mismatch")
        }

        return isTrusted
    }
}