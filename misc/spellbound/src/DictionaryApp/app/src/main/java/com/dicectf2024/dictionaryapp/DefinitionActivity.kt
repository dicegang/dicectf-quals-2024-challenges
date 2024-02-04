package com.dicectf2024.dictionaryapp

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.dicectf2024.dictionaryservice.IDictionaryService
import com.dicectf2024.dictionaryservice.ISignatureService
import com.dicectf2024.dictionaryapp.ui.theme.DictionaryAppTheme
import org.json.JSONObject
import java.io.IOException
import java.nio.charset.Charset
import org.json.JSONArray

class DefinitionActivity : ComponentActivity() {
    private val TAG: String = "dicectf:DictionaryApp:DefinitionActivity"

    private var signatureService: ISignatureService? = null
    private var dictionaryService: IDictionaryService? = null

    private var isSignatureServiceBound = false
    private var isDictionaryServiceBound = false

    private var pronunciation by mutableStateOf("")
    private var description by mutableStateOf("")
    private var seen by mutableStateOf("")
    private var etymology by mutableStateOf("")
    private var notes by mutableStateOf("")

    private lateinit var dictionaryServiceConnection: ServiceConnection
    private val signatureServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(componentName: ComponentName, service: IBinder) {
            val boundSignatureService = ISignatureService.Stub.asInterface(service)
            signatureService = boundSignatureService
            isSignatureServiceBound = true
            Log.d(TAG, "SignatureService: onServiceConnected called")

            val intent = Intent().setComponent(
                ComponentName(
                    "com.dicectf2024.dictionaryservice",
                    "com.dicectf2024.dictionaryservice.DictionaryService"
                )
            )
            val signedIntent = SignedIntent.make(applicationContext, intent, boundSignatureService)
            val bindingResult =
                bindService(signedIntent, dictionaryServiceConnection, Context.BIND_AUTO_CREATE)
            Log.d(TAG, "DictionaryService: binding result=$bindingResult")
        }

        override fun onServiceDisconnected(componentName: ComponentName) {
            isSignatureServiceBound = false
            signatureService = null
            Log.d(TAG, "SignatureService: onServiceDisconnected called")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val intent = Intent().setComponent(
            ComponentName(
                "com.dicectf2024.dictionaryservice",
                "com.dicectf2024.dictionaryservice.SignatureService"
            )
        )
        val bindingResult = bindService(
            intent,
            signatureServiceConnection,
            Context.BIND_AUTO_CREATE
        )
        Log.d(TAG, "SignatureService: binding result=$bindingResult")

        val word = getRandomWord()
        Log.d(TAG, "word: $word")

        dictionaryServiceConnection = object : ServiceConnection {
            override fun onServiceConnected(componentName: ComponentName, service: IBinder) {
                dictionaryService = IDictionaryService.Stub.asInterface(service)
                isDictionaryServiceBound = true
                Log.d(TAG, "DictionaryService: onServiceConnected called")

                dictionaryService?.let {
                    val wordData = it.getData(word)
                    val jsonObject = JSONObject(wordData)
                    pronunciation = jsonObject.getString("pronunciation")
                    description = jsonObject.getString("description")
                    seen = jsonObject.getString("seen")
                    etymology = jsonObject.getString("etymology")
                    notes = jsonObject.getString("notes")
                }
            }

            override fun onServiceDisconnected(componentName: ComponentName) {
                isDictionaryServiceBound = false
                dictionaryService = null
                Log.d(TAG, "DictionaryService: onServiceDisconnected called")
            }
        }

        setContent {
            DictionaryAppTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    DefinitionActivityContent(word)
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        Log.d(TAG, "onPause called")
        unBindServices()
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "onDestroy called")
        unBindServices()
    }

    private fun unBindServices() {
        if (isSignatureServiceBound) {
            unbindService(signatureServiceConnection)
            isSignatureServiceBound = false
            signatureService = null
        }
        if (isDictionaryServiceBound) {
            unbindService(dictionaryServiceConnection)
            isDictionaryServiceBound = false
            dictionaryService = null
        }
    }

    @Composable
    fun DefinitionActivityContent(word: String) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = word,
                style = MaterialTheme.typography.headlineMedium,
            )
            if (pronunciation != "") {
                Text(
                    text = pronunciation,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(5.dp)
                )
            }
            if (description != "") {
                Spacer(modifier = Modifier.width(16.dp))
                Text(
                    text = "description",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(5.dp)
                )
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            if (seen != "") {
                Spacer(modifier = Modifier.width(16.dp))
                Text(
                    text = "seen",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(5.dp)
                )
                Text(
                    text = seen,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            if (etymology != "") {
                Spacer(modifier = Modifier.width(16.dp))
                Text(
                    text = "etymology",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(5.dp)
                )
                Text(
                    text = etymology,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            if (notes != "") {
                Spacer(modifier = Modifier.width(16.dp))
                Text(
                    text = "notes",
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(5.dp)
                )
                Text(
                    text = notes,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }

    private fun getRandomWord(): String {
        val dictionary = loadWords()
        return dictionary.random()
    }

    private fun loadWords(): List<String> {
        try {
            val inputStream = assets.open("words.json")
            val size = inputStream.available()
            val buffer = ByteArray(size)
            inputStream.read(buffer)
            inputStream.close()
            val json = String(buffer, Charset.forName("UTF-8"))
            val jsonArray = JSONArray(json)
            return (0 until jsonArray.length()).map { jsonArray.getString(it) }
        } catch (e: IOException) {
            e.printStackTrace()
        }
        return emptyList()
    }
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    DictionaryAppTheme {}
}