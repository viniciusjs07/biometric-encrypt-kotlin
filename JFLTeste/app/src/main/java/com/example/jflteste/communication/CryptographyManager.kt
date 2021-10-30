package com.example.jflteste.communication

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

interface CryptographyManager {

    /**
     * This method first gets or generates an instance of SecretKey and then initializes the Cipher
     * with the key. The secret key uses [ENCRYPT_MODE][Cipher.ENCRYPT_MODE] is used.
     */
    fun getInitializedCipherForEncryption(keyName: String): Cipher

    fun getBytesCypher(ctx: Context): ByteArray

    fun setBytesCypher(ctx: Context, bytes: ByteArray?)

    fun setBytesVectorArray(ctx: Context, bytes: ByteArray?)

    fun getBytesVectorArray(ctx: Context): ByteArray
    /**
     * This method first gets or generates an instance of SecretKey and then initializes the Cipher
     * with the key. The secret key uses [DECRYPT_MODE][Cipher.DECRYPT_MODE] is used.
     */
    fun getInitializedCipherForDecryption(keyName: String, initializationVector: ByteArray): Cipher

    /**
     * The Cipher created with [getInitializedCipherForEncryption] is used here
     */
    fun encryptData(plaintext: String, cipher: Cipher): EncryptedData

    /**
     * The Cipher created with [getInitializedCipherForDecryption] is used here
     */
    fun decryptData(ciphertext: ByteArray, cipher: Cipher): String

}

fun CryptographyManager(): CryptographyManager = CryptographyManagerImpl()

data class EncryptedData(val ciphertext: ByteArray, val initializationVector: ByteArray)

private class CryptographyManagerImpl : CryptographyManager {

    private val keySize: Int = 256
    val androidKeyStore = "AndroidKeyStore"
    val cypherInstanceJfl = "cypher_instance_jfl"
    val cypherEncrypt = "cypherEncrypt"
    val vectorInstanceJfl = "vector_instance_jfl"
    val vectorArrayJfl = "vectorArrayJfl"
    private val encryptionBlockMode = KeyProperties.BLOCK_MODE_GCM
    private val encryptionPadding = KeyProperties.ENCRYPTION_PADDING_NONE
    private val encryptionAlgorithm = KeyProperties.KEY_ALGORITHM_AES

    override fun getInitializedCipherForEncryption(keyName: String): Cipher {
        Log.d("KEYNAME ", keyName);
        val cipher = getCipher()
        val secretKey = getOrCreateSecretKey(keyName)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    override fun getInitializedCipherForDecryption(
        keyName: String,
        initializationVector: ByteArray
    ): Cipher {
        val cipher = getCipher()
        val secretKey = getOrCreateSecretKey(keyName)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, initializationVector))
        return cipher
    }

    override fun encryptData(plaintext: String, cipher: Cipher): EncryptedData {
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charset.forName("UTF-8")))
        return EncryptedData(ciphertext, cipher.iv)
    }

    override fun decryptData(ciphertext: ByteArray, cipher: Cipher): String {
        val plaintext = cipher.doFinal(ciphertext)
        return String(plaintext, Charset.forName("UTF-8"))
    }

    private fun getCipher(): Cipher {
        val transformation = "$encryptionAlgorithm/$encryptionBlockMode/$encryptionPadding"
        return Cipher.getInstance(transformation)
    }

    private fun getOrCreateSecretKey(keyName: String): SecretKey {
        // If Secretkey was previously created for that keyName, then grab and return it.
        val keyStore = KeyStore.getInstance(androidKeyStore)
        keyStore.load(null) // Keystore must be loaded before it can be accessed
        keyStore.getKey(keyName, null)?.let { return it as SecretKey }

        // if you reach here, then a new SecretKey must be generated for that keyName
        val paramsBuilder = KeyGenParameterSpec.Builder(
            keyName,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
        paramsBuilder.apply {
            setBlockModes(encryptionBlockMode)
            setEncryptionPaddings(encryptionPadding)
            setKeySize(keySize)
            setUserAuthenticationRequired(true)
        }

        val keyGenParams = paramsBuilder.build()
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            androidKeyStore
        )
        keyGenerator.init(keyGenParams)
        return keyGenerator.generateKey()
    }

    override fun getBytesVectorArray(ctx: Context): ByteArray {
        val prefs = ctx.getSharedPreferences(vectorInstanceJfl, AppCompatActivity.MODE_PRIVATE)
        val str = prefs.getString(vectorArrayJfl, null)
        return str?.toByteArray(StandardCharsets.ISO_8859_1)!!
    }

    override fun setBytesVectorArray(ctx: Context, bytes: ByteArray?) {
        val prefs = ctx.getSharedPreferences(vectorInstanceJfl, AppCompatActivity.MODE_PRIVATE)
        val e = prefs.edit()
        e.putString(vectorArrayJfl, String(bytes!!, StandardCharsets.ISO_8859_1))
        e.apply()
    }

    override fun setBytesCypher(ctx: Context, bytes: ByteArray?) {
        val prefs = ctx.getSharedPreferences(cypherInstanceJfl, AppCompatActivity.MODE_PRIVATE)
        val e = prefs.edit()
        e.putString(cypherEncrypt, String(bytes!!, StandardCharsets.ISO_8859_1))
        e.apply()
    }

    override fun getBytesCypher(ctx: Context): ByteArray {
        val prefs = ctx.getSharedPreferences(cypherInstanceJfl, AppCompatActivity.MODE_PRIVATE)
        val str = prefs.getString(cypherEncrypt, null)
        return str?.toByteArray(StandardCharsets.ISO_8859_1)!!
    }

}