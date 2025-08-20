import os
from jnius import autoclass, cast

def android_keystore_save(alias: str, password: str):
    """Store encryption keys in Android Keystore"""
    try:
        KeyStore = autoclass('java.security.KeyStore')
        KeyGenerator = autoclass('javax.crypto.KeyGenerator')
        KeyGenParameterSpec = autoclass('android.security.keystore.KeyGenParameterSpec')
        KeyProperties = autoclass('android.security.keystore.KeyProperties')
        
        # Initialize KeyStore
        ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(None)
        
        # Key generator setup
        kg = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, 
            "AndroidKeyStore"
        )
        
        # Key specification
        spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        ).setBlockModes([KeyProperties.BLOCK_MODE_GCM]) \
         .setEncryptionPaddings([KeyProperties.ENCRYPTION_PADDING_NONE]) \
         .setKeySize(256) \
         .setUserAuthenticationRequired(True) \
         .build()
        
        # Generate and store key
        kg.init(spec)
        kg.generateKey()
        
        return True
    except Exception as e:
        print(f"Keystore error: {str(e)}")
        return False

def android_biometric_authenticate():
    """Trigger biometric authentication"""
    try:
        BiometricManager = autoclass('androidx.biometric.BiometricManager')
        FragmentActivity = autoclass('androidx.fragment.app.FragmentActivity')
        BiometricPrompt = autoclass('androidx.biometric.BiometricPrompt')
        Executors = autoclass('java.util.concurrent.Executors')
        
        activity = autoclass('org.kivy.android.PythonActivity').mActivity
        executor = Executors.newSingleThreadExecutor()
        
        callback = BiometricPrompt.AuthenticationCallback()
        
        # Authentication callback handlers
        def on_auth_error(errorCode, errString):
            print(f"Biometric error: {errorCode} - {errString}")
        
        def on_auth_succeeded(result):
            print("Biometric authentication successful")
        
        def on_auth_failed():
            print("Biometric authentication failed")
        
        callback.onAuthenticationError = on_auth_error
        callback.onAuthenticationSucceeded = on_auth_succeeded
        callback.onAuthenticationFailed = on_auth_failed
        
        # Create biometric prompt
        prompt = BiometricPrompt(
            cast(FragmentActivity, activity),
            executor,
            callback
        )
        
        # Build prompt info
        PromptInfo = autoclass('androidx.biometric.BiometricPrompt$PromptInfo')
        builder = PromptInfo.Builder()
        builder.setTitle("Verify Identity")
        builder.setSubtitle("Authenticate to access encryption")
        builder.setNegativeButtonText("Cancel")
        prompt_info = builder.build()
        
        # Show authentication dialog
        prompt.authenticate(prompt_info)
        return True
    except Exception as e:
        print(f"Biometric error: {str(e)}")
        return False