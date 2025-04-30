# Flutter Private Key

This is a Flutter application that can do the followin:
* Generates an RSA private/public key pair, protects it via a password, and saves it in the Android Secure Storage.
* Retreive and show the keys saved in the Secure Storage.
* Delete the key from Android Secure Storage.
* Backup the keys to Google Drive hidden appData folder which is used for Android Application Configuration.
* Restore the keys from user Google Drive, and save them in the Secure Storage.
* If the user is not signed in, it can sign in the user and ask for consent to access user google drive appData hidden folder.
* Sign out the user and stop access to Google Drive.
