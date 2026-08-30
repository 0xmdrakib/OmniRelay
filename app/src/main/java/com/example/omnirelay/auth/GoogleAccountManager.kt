package com.example.omnirelay.auth

import android.content.Context
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialOption
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.NoCredentialException
import com.example.omnirelay.BuildConfig
import com.google.android.gms.tasks.Task
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.firebase.FirebaseApp
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.GoogleAuthProvider
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.SecureRandom
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

data class GoogleAccountProfile(
    val uid: String,
    val displayName: String,
    val email: String?
)

data class FirebaseAccountToken(val uid: String, val idToken: String)

class GoogleSignInCancelledException : IllegalStateException("Google sign-in was cancelled")
class NoAuthorizedGoogleAccountException : IllegalStateException("No authorized Google account is available")
class AccountAuthenticationRequiredException : IllegalStateException("Google account authentication is required")

/**
 * Credential Manager + Firebase Authentication bridge.
 *
 * Google profile details are displayed locally only. The relay backend receives a short-lived
 * Firebase ID token and stores only its verified UID when binding a cryptographic device identity.
 */
class GoogleAccountManager(private val activity: ComponentActivity) {
    private val credentialManager = CredentialManager.create(activity)

    val isConfigured: Boolean
        get() = BuildConfig.GOOGLE_WEB_CLIENT_ID.isNotBlank() &&
            BuildConfig.FIREBASE_API_KEY.isNotBlank() &&
            BuildConfig.FIREBASE_APP_ID.isNotBlank() &&
            BuildConfig.FIREBASE_PROJECT_ID.isNotBlank() &&
            FirebaseApp.getApps(activity).isNotEmpty()

    fun currentProfile(): GoogleAccountProfile? {
        if (!isConfigured) return null
        val user = FirebaseAuth.getInstance().currentUser ?: return null
        return user.toProfile()
    }

    suspend fun signIn(authorizedAccountsOnly: Boolean): GoogleAccountProfile {
        check(isConfigured) { "Google sign-in is not configured for this build" }
        val nonce = secureNonce()
        val option: CredentialOption = if (authorizedAccountsOnly) {
            GetGoogleIdOption.Builder()
                .setServerClientId(BuildConfig.GOOGLE_WEB_CLIENT_ID)
                .setFilterByAuthorizedAccounts(true)
                .setAutoSelectEnabled(true)
                .setNonce(nonce)
                .build()
        } else {
            GetSignInWithGoogleOption.Builder(BuildConfig.GOOGLE_WEB_CLIENT_ID)
                .setNonce(nonce)
                .build()
        }
        val request = GetCredentialRequest.Builder()
            .addCredentialOption(option)
            .build()
        val response = try {
            credentialManager.getCredential(activity, request)
        } catch (_: GetCredentialCancellationException) {
            throw GoogleSignInCancelledException()
        } catch (_: NoCredentialException) {
            throw NoAuthorizedGoogleAccountException()
        }
        val credential = response.credential as? CustomCredential
            ?: throw AccountAuthenticationRequiredException()
        if (credential.type != GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
            throw AccountAuthenticationRequiredException()
        }
        val googleCredential = runCatching { GoogleIdTokenCredential.createFrom(credential.data) }
            .getOrElse { throw AccountAuthenticationRequiredException() }
        val firebaseCredential = GoogleAuthProvider.getCredential(googleCredential.idToken, null)
        val result = FirebaseAuth.getInstance().signInWithCredential(firebaseCredential).awaitResult()
        return (result.user ?: throw AccountAuthenticationRequiredException()).toProfile()
    }

    suspend fun signOut() {
        clearFirebaseSession()
        runCatching { credentialManager.clearCredentialState(ClearCredentialStateRequest()) }
    }

    fun clearFirebaseSession() {
        if (FirebaseApp.getApps(activity).isNotEmpty()) FirebaseAuth.getInstance().signOut()
    }

    private fun secureNonce(): String = ByteArray(32)
        .also(SecureRandom()::nextBytes)
        .let { Base64.encodeToString(it, Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE) }

    private fun com.google.firebase.auth.FirebaseUser.toProfile(): GoogleAccountProfile {
        val safeEmail = email?.takeIf { it.length <= 320 }
        val safeName = displayName?.trim()?.takeIf { it.isNotEmpty() }?.take(120)
            ?: safeEmail?.substringBefore('@')?.take(120)
            ?: "Google user"
        return GoogleAccountProfile(uid = uid, displayName = safeName, email = safeEmail)
    }
}

object FirebaseAccountSession {
    fun isConfigured(context: Context): Boolean =
        BuildConfig.FIREBASE_API_KEY.isNotBlank() &&
            BuildConfig.FIREBASE_APP_ID.isNotBlank() &&
            BuildConfig.FIREBASE_PROJECT_ID.isNotBlank() &&
            BuildConfig.GOOGLE_WEB_CLIENT_ID.isNotBlank() &&
            FirebaseApp.getApps(context).isNotEmpty()

    fun isSignedIn(context: Context): Boolean =
        isConfigured(context) && FirebaseAuth.getInstance().currentUser != null

    suspend fun idToken(context: Context, forceRefresh: Boolean = false): FirebaseAccountToken {
        if (!isConfigured(context)) throw AccountAuthenticationRequiredException()
        val user = FirebaseAuth.getInstance().currentUser ?: throw AccountAuthenticationRequiredException()
        val token = runCatching { user.getIdToken(forceRefresh).awaitResult().token }
            .getOrNull()
            ?: throw AccountAuthenticationRequiredException()
        require(token.length in 100..16_384) { "Firebase ID token length is invalid" }
        return FirebaseAccountToken(uid = user.uid, idToken = token)
    }
}

private suspend fun <T> Task<T>.awaitResult(): T = suspendCancellableCoroutine { continuation ->
    addOnCompleteListener { task ->
        if (!continuation.isActive) return@addOnCompleteListener
        if (task.isSuccessful) {
            @Suppress("UNCHECKED_CAST")
            continuation.resume(task.result as T)
        } else {
            continuation.resumeWithException(
                task.exception ?: AccountAuthenticationRequiredException()
            )
        }
    }
}
