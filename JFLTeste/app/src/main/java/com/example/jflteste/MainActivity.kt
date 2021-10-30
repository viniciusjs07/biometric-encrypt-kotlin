package com.example.jflteste

import android.os.Bundle
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.AppCompatEditText
import androidx.appcompat.widget.AppCompatTextView
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.navigation.findNavController
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.navigateUp
import androidx.navigation.ui.setupActionBarWithNavController
import com.example.jflteste.communication.CryptographyManager
import com.example.jflteste.databinding.ActivityMainBinding
import com.google.android.material.snackbar.Snackbar
import java.nio.charset.Charset
import java.util.concurrent.Executor
import android.content.Context

import java.nio.charset.StandardCharsets.ISO_8859_1


class MainActivity : AppCompatActivity() {

    private lateinit var appBarConfiguration: AppBarConfiguration
    private lateinit var binding: ActivityMainBinding
    private lateinit var btnAuth: Button
    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private lateinit var secretKeyName: String
    private lateinit var cryptographyManager: CryptographyManager
    private lateinit var textInputViewEmail: AppCompatEditText
    private lateinit var textInputViewPassword: AppCompatEditText
    private lateinit var textOutputView: AppCompatTextView
    private lateinit var initializationVector: ByteArray
    private lateinit var initializationVector2: ByteArray
    private var readyToEncrypt: Boolean = false
    private lateinit var ciphertext: ByteArray


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
//        shared = getSharedPreferences("INSTANCE_VECTOR", Context.MODE_PRIVATE)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
//        btnAuth = findViewById(R.id.btnAuth);

        val navController = findNavController(R.id.nav_host_fragment_content_main)
        appBarConfiguration = AppBarConfiguration(navController.graph)
        setupActionBarWithNavController(navController, appBarConfiguration)

        cryptographyManager = CryptographyManager()

        secretKeyName = getString(R.string.secret_key_name)

        biometricPrompt = createBiometricPrompt()

        promptInfo = createPromptInfo();


        textInputViewEmail = findViewById(R.id.etEmail)
        textOutputView = findViewById(R.id.tvLogin)
        findViewById<Button>(R.id.btnEncrypt).setOnClickListener { authenticateToEncrypt() }
        findViewById<Button>(R.id.btnDecrypt).setOnClickListener { authenticateToDecrypt() }
//        biometricPrompt.authenticate(promptInfo)
//        val biometricLoginButton =
//            findViewById<Button>(R.id.btnAuth)
//        biometricLoginButton.setOnClickListener {
//            biometricPrompt.authenticate(promptInfo)
//        }


        binding.fab.setOnClickListener { view ->
            Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                .setAction("Action", null).show()
        }
    }


    private fun createPromptInfo(): BiometricPrompt.PromptInfo {
        return BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric login for my app")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Use account password")
//            .setDeviceCredentialAllowed(BIOMETRIC_STRONG)
            .build()

    }

    private fun createBiometricPrompt(): BiometricPrompt {
        executor = ContextCompat.getMainExecutor(this)
        return BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence
                ) {
                    super.onAuthenticationError(errorCode, errString)
//                    tvAuthStatus.text = " Authentication Error "
                    Toast.makeText(
                        applicationContext,
                        "Authentication error: $errString", Toast.LENGTH_SHORT
                    )
                        .show()
                }

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    super.onAuthenticationSucceeded(result)
//                    tvAuthStatus.text = " Authentication Success "
                    processData(result.cryptoObject)
                    Toast.makeText(
                        applicationContext,
                        "Authentication succeeded!", Toast.LENGTH_SHORT
                    ).show()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
//                    tvAuthStatus.text = " Authentication Failed "
                    Toast.makeText(
                        applicationContext, "Authentication failed",
                        Toast.LENGTH_SHORT
                    )
                        .show()
                }
            })
    }

    private fun authenticateToEncrypt() {
        readyToEncrypt = true
        Log.d(
            "CLICK",
            "CLICK ENCRYPT = " + BiometricManager.from(applicationContext)
                .canAuthenticate(BIOMETRIC_STRONG)
        );
        if (BiometricManager.from(applicationContext)
                .canAuthenticate(BIOMETRIC_STRONG) == BiometricManager
                .BIOMETRIC_SUCCESS
        ) {
            val cipher = cryptographyManager.getInitializedCipherForEncryption(secretKeyName)
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        } else {
            Toast.makeText(
                applicationContext,
                "Seu dispositivo não possui autenticação por Biometria", Toast.LENGTH_SHORT
            )
                .show()
        }
    }

    private fun authenticateToDecrypt() {
        readyToEncrypt = false
        if (BiometricManager.from(applicationContext)
                .canAuthenticate(BIOMETRIC_STRONG) == BiometricManager
                .BIOMETRIC_SUCCESS
        ) {
            ciphertext = cryptographyManager.getBytesCypher(this)
            Log.e("CYPPPPER ", ciphertext.toString());
            val cipher = cryptographyManager.getInitializedCipherForDecryption(
                secretKeyName,
                cryptographyManager.getBytesVectorArray(this)
            )
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        } else {
            Toast.makeText(
                applicationContext,
                "Seu dispositivo não possui autenticação por Biometria", Toast.LENGTH_SHORT
            )
                .show()
        }

    }


    private fun processData(cryptoObject: BiometricPrompt.CryptoObject?) {
        val data = if (readyToEncrypt) {
            val text = textInputViewEmail.text.toString()
            Log.d("PASSWORD  ", text)
            val encryptedData = cryptographyManager.encryptData(text, cryptoObject?.cipher!!)
            ciphertext = encryptedData.ciphertext
            initializationVector = encryptedData.initializationVector

//            val editor = shared.edit()
//            Log.e("initializationVector", initializationVector.contentToString())
//            editor.putString("myByteArray", initializationVector.contentToString())
//            editor.apply()
            cryptographyManager.setBytesCypher(this, ciphertext)
            cryptographyManager.setBytesVectorArray(this, initializationVector)

            String(ciphertext, Charset.forName("UTF-8"))
        } else {
            cryptographyManager.decryptData(ciphertext, cryptoObject?.cipher!!)
        }
        Log.d("DATAAA ", data)
        textOutputView.text = data
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        return when (item.itemId) {
            R.id.action_settings -> true
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        val navController = findNavController(R.id.nav_host_fragment_content_main)
        return navController.navigateUp(appBarConfiguration)
                || super.onSupportNavigateUp()
    }

}