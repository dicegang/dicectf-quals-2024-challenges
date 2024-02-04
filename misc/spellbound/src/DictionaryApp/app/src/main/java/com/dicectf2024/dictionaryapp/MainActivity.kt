package com.dicectf2024.dictionaryapp

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import android.content.ActivityNotFoundException
import android.widget.Toast
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.dicectf2024.dictionaryapp.ui.theme.DictionaryAppTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            DictionaryAppTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainActivityContent()
                }
            }
        }
    }

    private fun launchDefinitionActivity() {
        val intent = Intent(this, DefinitionActivity::class.java)
        try {
            startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            Toast.makeText(this, "No matching activity found", Toast.LENGTH_SHORT).show()
        }
    }

    @Composable
    fun MainActivityContent() {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "magic dictionary",
                style = MaterialTheme.typography.headlineLarge,
                modifier = Modifier.padding(9.dp)
            )
            Spacer(modifier = Modifier.width(16.dp))
            Button(
                onClick = {
                    launchDefinitionActivity()
                },
                modifier = Modifier
                    .padding(top = 16.dp)
            ) {
                Text("i'm feeling lucky")
            }
        }
    }
}