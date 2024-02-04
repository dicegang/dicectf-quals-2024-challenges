# spellbound (dicectf2024)

Category: misc/android
Authors: orion, hpmv

* [Android Studio](https://developer.android.com/studio) is recommended
* challenge apps were tested on Pixel 3a AVD API 34

## files

`spellbound.zip` has the files that should be distributed in the challenge download:
* DictionaryApp-signed.apk
* DictionaryService-signed.apk

There's no obfuscation, we expect people to just go decompile the apks.

Both apps are signed so they can be installed on the emulator. The key used to sign both apps to create the hardcoded signature in the apps' identity check is included in the repo. Since this key is pretty related to the challenge the keystore is included in this repo for reproducibility reasons,
but it goes without saying don't use this keystore for anything important etc.

## description

This challenge required exploiting a behavior of [Android bound services](https://developer.android.com/develop/background-work/services/bound-services). Namely this part:
> You can connect multiple clients to a service simultaneously. However, the system caches the IBinder service communication channel. In other words, the system calls the service's onBind() method to generate the IBinder only when the first client binds. The system then delivers that same IBinder to all additional clients that bind to that same service, without calling onBind() again.

### DictionaryService
This app exports two services:
* SignatureService
* DictionaryService

SignatureService is only accessible if you have the permission `com.dicectf2024.permission.dictionary.BIND_SIGNATURE_SERVICE` declared in the manifest. This permission is only available to apps signed with the same signing key due to `protectionLevel="signature"`. It's intended that this is only accessible from DictionaryApp.

DictionaryService is the interesting service that serves a bunch of words and their definitions. If the magic word is received (`flag`), it returns the flag token, which is a 16-character random string stored in [Encrypted Shared Preferences](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences#). This is to ensure it cannot be accessed by another app by normal means.

Even though this service is exported, this service is only intended to be bound to from DictionaryApp. To ensure this, it has a permission check in `onBind` that is pretty restrictive:
1. First, the incoming intent must have two signed extras. It must be signed with a key in DictionaryService's keystore. The only way to achieve this outside the app is through SignatureService, which is only accessible to apps signed with the same signing key.
2. The signed extras contains a timestamp and a package name. The timestamp must not be expired and the package name must match DictionaryApp.
3. Finally, it queries PackageManager to verify that only a single app on the entire system has the `BIND_SIGNATURE_SERVICE` permission, as well as that that single app matches DictionaryApp's package name and signature. Even if you somehow managed to sign an app with the same key, if there are more apps with this permission the check will fail.

If any of these checks fail, `onBind` will just return `null` as the binder interface and not the actual binder.

### DictionaryApp
This app has an exported activity that other apps can launch. The activity will bind to DictionaryService in `onCreate`, send a word to it, receive a defintion back, and display it onscreen.

Note it also unbinds the services upon navigating away, this is intended so you don't accidentally stumble on the solution if you had DictionaryApp open already while launching AttackerApp directly from Android Studio or something.

## solution

The solution is to write an attacker app that
1. Launches DictionaryApp, triggering it to bind to DictionaryService
2. Tries to bind to DictionaryService after DictionaryApp has successfully binded. Since `onBind` is only ever called once and the same interface is returned to all clients, this bypasses the permission check. Now you can call `getData` on the service with the word `flag` to get flag, and print it out in logcat (which the solve service will give you)

The easiest is just to sleep for a few seconds after launching DictionaryApp's DefinitionActivity and then try to call `bindService`. Or you can start another service that binds to DictionaryService.

Note that if an untrusted app tries to bind to DictionaryService with an intent without the proper identity, DictionaryService will just return `null`. The result of `bindService` will still show as `true` but you can't do anything with this interface.

## Infrastructure

The evaluation infra for this challenge (not included in the source code here)
was hosted externally and heavily based on
https://github.com/google/android-emulator-container-scripts . Contact hpmv or
orion if you are interested in the infrastructure setup.
