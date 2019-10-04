/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.android.e3kitusage

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.*
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.common.callback.OnCompleteListener
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.keyknox.exception.EntryAlreadyExistsException
import com.virgilsecurity.keyknox.exception.EntryNotFoundException
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException
import com.virgilsecurity.sdk.jwt.JwtGenerator
import java.util.*
import java.util.concurrent.TimeUnit
import kotlin.random.Random

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

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
                        is EntryNotFoundException, is WrongPasswordException -> {
                            ethree.rotatePrivateKey()

                            ethree.backupPrivateKey(PASSWORD)
                        }
                    }
                }
            }
        }
        ethree.encrypt(TEXT)
    }

    val rotationConfirmed = Random.nextBoolean()
    val backupPrivateKeyConfirmed = Random.nextBoolean()
    val userSignedIn = Random.nextBoolean()
    val chosenSignIn = Random.nextBoolean()
    val chosenSignUp = Random.nextBoolean()
    val chosenLogOut = Random.nextBoolean()

    val password = UUID.randomUUID().toString()
    val tokenBase64String = UUID.randomUUID().toString()
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

    lateinit var ethree: EThree

    // This function should fetch Virgil JWT from your backend and return it as Base64 String.
    // You have to provide identity in your request that is required by backend
    // in JwtGenerator#generateToken function.
    // See https://github.com/VirgilSecurity/demo-backend-java#virgil-jwt-generation
    fun getTokenSynchronously(identity: String): String {
        val tokenBase64String = // TODO Get token from your backend

        return tokenBase64String
    }

    // Any custom or third-party auth system. (e.g. Firebase)
    fun signIn() {

    }

    // Any custom or third-party auth system. (e.g. Firebase)
    fun signUp() {

    }

    // Basic flow contains 3 usual cases:
    // 1) User already Signed In;
    // 2) User wants to Sign In;
    // 3) User wants to Sign Up;
    //
    // It's up to developer to determine what's the current case.
    //
    // For example you can use Firebase:
    // call FirebaseAuth#currentUser to check whether the user is Signed In. If user is not
    // Signed In - call one of:
    // FirebaseAuth#createUserWithEmailAndPassword or FirebaseAuth#signInWithEmailAndPassword.

    fun e3kitInitPoint() {
        // The place where all utilities are initialized. (e.g. in Application, MainActivity)
        val onGetTokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return getTokenSynchronously(identity)
            }
        }
        // identity has to be the same as in Virgil JWT, so requests for current user are authorized.
        // context can be any. (e.g. MainActivity's context, Application's context)
        val ethree = EThree(identity, onGetTokenCallback, this)

        if (userSignedIn) { // It's up to developer to know whether user is Signed In.
            flowOne()
        } else {
            if (chosenSignIn) {
                flowTwo()
            } else if (chosenSignUp) {
                flowThree()
            }
        }

        // Best practice is to remove private key from device after the session is closed. (e.g. Log Out)
        if (chosenLogOut) {
            ethree.cleanup()
        }
    }

    // 1) User already Signed In
    fun flowOne() {
        // Check if the user has private key on device.
        if (ethree.hasLocalPrivateKey()) {
            // If private key of current e3kit user is present - it means all is set up.
            val encrypted = ethree.encrypt("Text") // Encrypted for the current e3kit user herself.
        } else {
            // There's no private key on device.
            // There're three common cases:
            // 1.a) private key is in the Virgil cloud (backed up earlier)
            // 1.b) private key is on the other device but not in the Virgil cloud (needs to be backed up)
            // 1.c) private key is lost (there's no backup)

            // Try to restore private key from it's backup in Virgil cloud.
            ethree.restorePrivateKey(password).addCallback(object : OnCompleteListener {
                override fun onSuccess() {
                    // 1.a) private key is in the Virgil cloud (backed up earlier)
                    // private key has been restored - all is set up.
                    val encrypted = ethree.encrypt("Text") // Encrypted for the current e3kit user herself.
                }

                override fun onError(throwable: Throwable) {
                    if (throwable is PrivateKeyNotFoundException) {
                        // Actually in this situation you can't know whether it's 1.b or 1.c
                        // We recommend to ask the user for confirmation that the key has been lost.

                        // 1.b) private key is on the other device but not in the Virgil cloud (needs to be backed up)
                        // In case user responds that the key has not been lost - ask her to make a
                        // backup from the device that has private key locally.
                        // Then try to complete the flowOne again.

                        // In case user responds that the key has been lost - ask user to confirm
                        // the rotation of keys, so all previous history will become Undecryptable.
                        // If user confirms that - proceed with 1.c.

                        // 1.c) private key is lost (there's no backup)
                        if (rotationConfirmed) {
                            ethree.rotatePrivateKey().addCallback(object : OnCompleteListener {
                                override fun onSuccess() {
                                    val encrypted = ethree.encrypt("Text") // Encrypted for the current e3kit user herself.
                                }

                                override fun onError(throwable: Throwable) {
                                    // TODO Implement body or it will be empty ):
                                }
                            })
                        }
                    } else if (throwable is WrongPasswordException) {
                        // User provided wrong password
                        // Ask other password and try again flowOne.
                    } else if (throwable is RestoreKeyException) {
                        // restorePrivateKey function can restore private key only if there's no one present
                        // on the device locally, but the private key is already present on the device.
                        // you have to call ethree.cleanup() first in order to remove local private key.
                        //
                        // It's impossible to get here in current flow, but restorePrivateKey function
                        // can be called in other flows when private key is present on device locally.
                    }
                }
            })
        }
    }

    // 2) User wants to Sign In
    fun flowTwo() {
        ethree.register().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                // User has been registered successfully. Private key is now on device locally.
                val encrypted = ethree.encrypt("Text") // Encrypted for the current e3kit user herself.

                // You have to decide to ask the user or to backup private key automatically.
                if (backupPrivateKeyConfirmed) { // If backup is in user-confirmation flow.
                    ethree.backupPrivateKey(password).addCallback(object : OnCompleteListener {
                        override fun onSuccess() {
                            // You're good to go. Now you can EThree#restorePrivateKey on other
                            // devices.
                        }

                        override fun onError(throwable: Throwable) {
                            if (throwable is BackupKeyException) {
                                // You get here if there's already private key backup in Virgil cloud
                                // with current user's identity.
                            } else if (throwable is PrivateKeyNotFoundException) {
                                // You get here if there no private key has been found locally.
                                // It's impossible to get here in current flow, but if you call
                                // EThree#cleanup before backup - you can get in this situation.
                            }
                        }
                    })
                }
            }

            override fun onError(throwable: Throwable) {
                if (throwable is AlreadyRegisteredException) {
                    // e3kit user with provided identity has been already registered
                } else if (throwable is PrivateKeyPresentException) {

                } else if (throwable is CryptoException) {

                }
            }
        })
    }

    // 3) User wants to Sign Up
    fun flowThree() {

    }


    companion object {
        private const val TEXT = "TEXT"
        private const val PASSWORD = "PASSWORD"
    }
}
