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

import androidx.appcompat.app.AppCompatActivity
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.*
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.common.callback.OnCompleteListener
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException
import java.lang.IllegalStateException
import java.util.*
import kotlin.random.Random

class MainActivity : AppCompatActivity() {

    // --------------------------------------------------------------------------------------------
    // variables just to avoid compiler errors ----------------------------------------------------
    // --------------------------------------------------------------------------------------------
    val rotationConfirmed = Random.nextBoolean()
    val backupPrivateKeyConfirmed = Random.nextBoolean()
    val userSignedIn = Random.nextBoolean()
    val chosenSignIn = Random.nextBoolean()
    val chosenSignUp = Random.nextBoolean()
    val chosenSignOut = Random.nextBoolean()
    val userAuthState = Random.nextInt(0, 3).let { // Defined by developer in real app
        when (it) {
            0 -> AUTH_STATE.USER_SIGNED_IN
            1 -> AUTH_STATE.USER_WANTS_TO_SIGN_IN
            2 -> AUTH_STATE.USER_WANTS_TO_SIGN_UP
            3 -> AUTH_STATE.USER_WANTS_TO_SIGN_OUT
            else -> throw IllegalStateException()
        }
    }

    val password = UUID.randomUUID().toString()
    val tokenBase64String = UUID.randomUUID().toString()
    val identity = UUID.randomUUID().toString()

    lateinit var ethree: EThree

    enum class AUTH_STATE {
        USER_SIGNED_IN,
        USER_WANTS_TO_SIGN_IN,
        USER_WANTS_TO_SIGN_UP,
        USER_WANTS_TO_SIGN_OUT
    }

    // -------------------------------------------------------------------------------------------
    // Beginning of usage example with exceptions description ------------------------------------
    // -------------------------------------------------------------------------------------------

    // This function should fetch a Virgil JWT from your backend and return it as Base64 String.
    // You have to provide an identity in your request that is required by your backend
    // in the JwtGenerator#generateToken function.
    // See https://github.com/VirgilSecurity/demo-backend-java#virgil-jwt-generation
    fun getTokenSynchronously(identity: String): String {
        val tokenBase64String = // TODO Get token from your backend

        return tokenBase64String
    }

    /*
     * Basic flow contains 3 usual cases:
     * 1) User is already Signed In;
     * 2) User wants to Sign In;
     * 3) User wants to Sign Up;
     * 4) User wants to Sign Out;
     *
     * It's up to you to determine what the current case is.
     */
    fun e3kitInitPoint() {
        // The place where all utilities are initialized.
        // (e.g. in Application#onCreate, MainActivity#onCreate)
        val onGetTokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return getTokenSynchronously(identity)
            }
        }
        // The identity has to be the same used to generate the Virgil JWT, so requests for the current user are authorized.
        // Context can be any. (e.g. MainActivity's context, Application's context)
        val ethree = EThree(identity, onGetTokenCallback, this)

        // It's up to you to check the authorization state.
        when (userAuthState) {
            AUTH_STATE.USER_SIGNED_IN -> userAlreadySignedIn() // Checked on app startup
            AUTH_STATE.USER_WANTS_TO_SIGN_IN -> userWantsToSignIn() // E.g. on button click
            AUTH_STATE.USER_WANTS_TO_SIGN_UP -> userWantsToSignUp() // E.g. on button click

            // 4) User wants to Sign Out
            // It's a good practice to remove the private key from the device after the session is closed. (e.g. Log Out)
            AUTH_STATE.USER_WANTS_TO_SIGN_OUT -> ethree.cleanup() // E.g. on button click
        }
    }

    // 1) User is already Signed In.
    fun userAlreadySignedIn() {
        // Check whether private key is present on the device locally.
        if (ethree.hasLocalPrivateKey()) {
            // If private key of current E3Kit user is present - it means all is set up.
            val encrypted = ethree.encrypt("Text") // Encrypted only for the current user.
        } else {
            tryToRestorePrivateKey()
        }
    }

    // 2) User wants to Sign In
    fun userWantsToSignIn() {
        // Check whether private key is present on the device locally.
        if (ethree.hasLocalPrivateKey()) {
            // This is not recommended.
            // You should remove the private key from the device after the session ends.
            // But, although less secure, you can proceed using E3Kit this way.
            val encrypted = ethree.encrypt("Text") // Encrypted only for the current user.
        } else {
            // Usually, in this step, you should have your private key removed, but keep its backup on
            // Virgil Cloud.

            tryToRestorePrivateKey()
        }
    }

    // 3) User wants to Sign Up
    fun userWantsToSignUp() {
        // Try to register E3Kit user (publishes public key, and saves the private key locally on the device)
        ethree.register().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                // User has been registered successfully. Private key is now on the device locally.
                val encrypted = ethree.encrypt("Text") // Encrypted only for the current user.

                // You have to decide whether to backup the private key automatically or to ask the user first.

                if (backupPrivateKeyConfirmed) { // If backup is in user-confirmation flow.
                    ethree.backupPrivateKey(password).addCallback(object : OnCompleteListener {
                        override fun onSuccess() {
                            // You're good to go. Now you can EThree#restorePrivateKey on other
                            // devices.
                        }

                        override fun onError(throwable: Throwable) {
                            if (throwable is BackupKeyException) {
                                // You get here if there's already private key backup present in the
                                // Virgil Cloud with the current user's identity.
                                //
                                // In the current flow, this is a sign that you have issues with your
                                // authorization system, because, in Sign Up, the user hasn't
                                // registered yet (not in your auth system nor in E3Kit).
                                // So Virgil Cloud should not contain a private key backup for this
                                // identity yet.
                                //
                                // If you are sure that this is an intended situation - you can call
                                // EThree#resetPrivateKeyBackup(pwd) to remove the private key backup
                                // from Virgil Cloud. After this you can call
                                // EThree#backupPrivateKey once more to complete the backup with a new key.
                            } else if (throwable is PrivateKeyNotFoundException) {
                                // You get here if there's no private key locally.
                                //
                                // It's impossible to get here in current flow, but if you call
                                // EThree#cleanup before EThree#backupPrivateKey - you can get into
                                // this situation.
                                //
                                // You've probably deleted your private key before making its
                                // backup. Since this is a Sign Up flow, you shouldn't have a backup yet.
                                // If by any accident you already have a private key backup - you
                                // can restore it with EThree#restorePrivateKey.
                                // In the usual case (it's your real first EThree#register and you don't
                                // have any backups yet) the only thing you can do is
                                // EThree#rotatePrivateKey, so a new key pair will be generated, and
                                // the old one will be replaced with the new one. After successful
                                // rotation you can call EThree#backupPrivateKey once more to
                                // complete the backup with a new key.
                            }
                        }
                    })
                }
            }

            override fun onError(throwable: Throwable) {
                if (throwable is AlreadyRegisteredException) {
                    // An E3Kit user with the provided identity has been already registered.
                    //
                    // You got here because something went wrong with SignIn or SignUp.
                    // SignUp or EThree#register should not be called if a user has already been registered.
                    //
                    // If you are sure that this is an intended behavior and you want to register
                    // a user with the same identity (re-register) - you can call:
                    // EThree#unregister -> EThree#register
                    // or
                    // EThree#rotatePrivateKey
                    // (all old keys for this identity will become outdated)
                } else if (throwable is PrivateKeyPresentException) {
                    // This exception means that the private key is already present on the device
                    // locally.
                    //
                    // If you are sure that the local private key is not needed (it was generated with
                    // Virgil Core SDK by accident, or by calling EThree#register twice, or any other
                    // case) any more - you can call EThree#cleanup, after which you can call EThree#register
                    // once more to complete the registration.
                } else if (throwable is CryptoException) {
                    // This exception could be thrown if there was an exception while generating
                    // keys during EThree#register.
                    //
                    // The only thing you can do is to try and call EThree#register once more.
                    //
                    // This behavior is not expected in any cases. If it happens, it's better to contact
                    // the Virgil Security team with a full log.
                }
            }
        })
    }

    private fun tryToRestorePrivateKey() {
        // There's no private key on the device.
        //
        // There're three common cases:
        // a) Private key is on Virgil Cloud (backed up earlier).
        // b) Private key is on another device but not on Virgil Cloud (needs to be backed up).
        // c) Private key has been lost (there's no backup).

        // Try to restore private key from its backup on Virgil Cloud.
        ethree.restorePrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                // a) Private key is on Virgil Cloud (backed up earlier)
                // private key has been restored - all is set up.
                val encrypted = ethree.encrypt("Text") // Encrypted for the current E3Kit user herself.
            }

            override fun onError(throwable: Throwable) {
                if (throwable is NoPrivateKeyBackupException) {
                    // Actually in this situation you can't know whether it's b) or c).
                    // We recommend to ask the user for confirmation that the key has been lost.

                    // b) Private key is on the other device but not on Virgil Cloud (needs to be backed up).
                    // In case user responds that the key has Not been lost - ask her to make a
                    // backup from the device that has private key locally.
                    // Then try to complete the tryToRestorePrivateKey again.

                    // In case user responds that the key has been lost - ask user to confirm
                    // the rotation of keys, so all previous history will become Undecryptable.
                    // If user confirms that - proceed with c).

                    // c) Private key has been lost (there's no backup).
                    if (rotationConfirmed) {
                        ethree.rotatePrivateKey().addCallback(object : OnCompleteListener {
                            override fun onSuccess() {
                                // New public key has been published to the Virgil Cards service.
                                // New private key has been saved locally on the device.
                                //
                                // You could want to make a private key backup right away after keys
                                // rotation, so you can call EThree#backupPrivateKey. Please, see
                                // possible errors for EThree#backupPrivateKey in userWantsToSignUp
                                // function.
                                //
                                // Don't forget that all other users might have your outdated (old)
                                // public key.
                                // You have to update it to the actual one on other user's devices.
                                val encrypted = ethree.encrypt("Text") // Encrypted for the current E3Kit user herself.
                            }

                            override fun onError(throwable: Throwable) {
                                if (throwable is PrivateKeyPresentException) {
                                    // EThree#rotatePrivateKey function can rotate keys only if there's no private key present
                                    // on the device locally, but the private key is already present on the device.
                                    //
                                    // It's impossible to get here in current flow, but EThree#rotatePrivateKey function
                                    // can be called in other flows when private key is present on the device locally.
                                    //
                                    // You have to call EThree#cleanup in order to remove local private key.
                                    // As well you can check EThree#hasLocalPrivateKey before calling EThree#rotatePrivateKey.
                                } else if (throwable is UserNotRegisteredException) {
                                    // Thrown if EThree#rotatePrivateKey is called before EThree#register.
                                    // Means that there is no E3Kit User registered yet (No public key
                                    // for current identity in Virgil Cards service is present).
                                    //
                                    // You cannot get this exception in current flow. But you can
                                    // get this exception if you call EThree#rotatePrivateKey, or
                                    // EThree#unregister before EThree#register has finished
                                    // successfully.
                                    //
                                    // This signals you that you have issues with your authorization
                                    // system, because user is already Signed In, while is not
                                    // registered yet.
                                    // If this by any case is an intended situation - you can register
                                    // user with EThree#register.
                                } else if (throwable is CryptoException) {
                                    // This exception could be thrown if there was an exception while generating
                                    // keys during the EThree#register.
                                    //
                                    // The only thing you can do - try to call EThree#register once more.
                                    //
                                    // All known E3Kit use-cases do not throw this exception. It's better to contact
                                    // developer in case of this exception.
                                }
                            }
                        })
                    }
                } else if (throwable is WrongPasswordException) {
                    // User provided wrong password. (Different from the one that had been used for
                    // the EThree#backupPrivateKey)
                    //
                    // Ask other password and try again to restore private key.
                    // WARNING! You have to wait 2+ seconds before sequential call to
                    // EThree#restorePrivateKey. If you don't - you'll get throttling error from
                    // Virgil Cloud.
                } else if (throwable is PrivateKeyPresentException) {
                    // EThree#restorePrivateKey function can restore private key only if there's no one present
                    // But the private key is already present on the device.
                    //
                    // It's impossible to get here in the current flow, but EThree#restorePrivateKey
                    // can be called in other flows when the private key is present locally on the device.
                    //
                    // You have to call EThree#cleanup in order to remove the local private key.
                    // You can also check EThree#hasLocalPrivateKey before calling EThree#restorePrivateKey.
                }
            }
        })
    }
}
