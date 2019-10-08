package com.virgilsecurity.android.e3kitusage

import androidx.appcompat.app.AppCompatActivity
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.AlreadyRegisteredException
import com.virgilsecurity.android.common.exception.NoPrivateKeyBackupException
import com.virgilsecurity.android.common.exception.WrongPasswordException
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.jwt.JwtGenerator
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * BlockScheme
 */
class BlockScheme : AppCompatActivity() {

    fun implementation() {
        val identity = UUID.randomUUID().toString()
        val virgilCrypto = VirgilCrypto()

        val privateKeyData = Data.fromBase64String("MC4CAQAwBQYDK2VwBCIEIPupM43Dt7" +
                "gJwayKl6EO4qFJbvyALQxap1LcgqoYVREb")
        val apiKey = virgilCrypto.importPrivateKey(privateKeyData.data).privateKey

        val jwtGenerator = JwtGenerator(
            "54e071c5c1894aa889e31d6c7864fed5",
            apiKey,
            "MCowBQYDK2VwAyEAeAkxVayBD3F4kGQoa1Mtlgqip5jxBXmPG5JP8PXopQI=",
            TimeSpan.fromTime(600, TimeUnit.SECONDS),
            VirgilAccessTokenSigner(virgilCrypto)
        )

        val onGetTokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return jwtGenerator.generateToken(identity).stringRepresentation()
            }
        }


        // Implementation of e3kit usage block-scheme
        val ethree = EThree(identity, onGetTokenCallback, this)

        if (!ethree.hasLocalPrivateKey()) {
            try {
                ethree.register().execute()

                ethree.backupPrivateKey(PASSWORD)
            } catch (exception: AlreadyRegisteredException) {
                try {
                    ethree.restorePrivateKey(PASSWORD)
                } catch (exception: Exception) {
                    when (exception) {
                        is NoPrivateKeyBackupException, is WrongPasswordException -> {
                            ethree.rotatePrivateKey()

                            ethree.backupPrivateKey(PASSWORD)
                        }
                    }
                }
            }
        }
        ethree.encrypt(TEXT)
    }

    companion object {
        private const val TEXT = "TEXT"
        private const val PASSWORD = "PASSWORD"
    }
}
