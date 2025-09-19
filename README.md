# Secure File System Client

## Project Goal

The objective of this project is to implement the client-side logic for a secure file storage and sharing system. The core security principle is that the server (datastore and keystore) is **completely untrusted**. All cryptographic operations—encryption, decryption, message authentication, and digital signatures—are performed exclusively on the client side.

This implementation guarantees the following critical security properties for all user and file data:
-   **Confidentiality**: All file content is end-to-end encrypted, meaning the server can never see the plaintext data.
-   **Integrity**: Any malicious modification of data stored on the server (e.g., file content, user access lists) can be detected by the client.
-   **Authenticity**: The identity of users is verified, and the origin of shared files and invitations can be authenticated.

All of the core logic is implemented in `client/client.go`.

---

## Core Functionality Implemented

### 1. User Management
-   **User Creation (`GetUser`)**: When a user is created, a public/private key pair is generated for digital signatures and key exchange. The user's password is used with a key derivation function (Argon2) to generate symmetric keys for encrypting their private key and other sensitive metadata.
-   **Authentication**: Users are authenticated locally by deriving keys from their password and verifying the integrity of their data structures.

### 2. File Operations
-   **Storing Files (`StoreFile`)**:
    1.  A unique, cryptographically-random symmetric key is generated for each file.
    2.  The file's content is encrypted using this key (AES-GCM for authenticated encryption).
    3.  A Message Authentication Code (HMAC-SHA256) is computed over the encrypted content to provide an additional layer of integrity protection.
    4.  The encrypted content and its HMAC are uploaded to the datastore.
-   **Loading Files (`LoadFile`)**:
    1.  The client downloads the encrypted content and its HMAC from the datastore.
    2.  It first verifies the HMAC to ensure the ciphertext has not been tampered with.
    3.  If the HMAC is valid, the client decrypts the content using the corresponding file key.
-   **Appending to Files (`AppendToFile`)**: Appending is implemented as an atomic load-decrypt-append-encrypt-store sequence to maintain the integrity and confidentiality of the entire file with each modification.

### 3. Secure File Sharing
-   **Creating Invitations (`CreateInvite`)**:
    1.  A user (the owner) can share a file with another user by creating a digitally signed "invitation" object.
    2.  The file's symmetric encryption key is encrypted using the recipient's public key (RSA or a similar asymmetric scheme).
    3.  This encrypted key, along with file metadata, is wrapped in an invitation structure, which is then digitally signed by the owner using their private signing key. This prevents the server or other malicious parties from forging invitations.
-   **Accepting Invitations (`AcceptInvite`)**:
    1.  The recipient downloads the invitation and first verifies the owner's digital signature.
    2.  If the signature is valid, the recipient uses their private key to decrypt the file's symmetric key.
    3.  The recipient now has access to the file and can use this key to load, decrypt, and modify it.

### 4. Access Revocation (`RevokeAccess`)
-   When a user's access to a file is revoked, the file's confidentiality must be preserved against the revoked user.
-   **Mechanism**:
    1.  The file owner generates a **new** symmetric key for the file.
    2.  The owner re-encrypts the file content with this new key.
    3.  The owner creates new "invitations" containing this new key for all **remaining, non-revoked** users who still have access.
    4.  This ensures that the revoked user, who only possesses the old key, can no longer decrypt the current or future versions of the file.

---

## Cryptographic Primitives Used

-   **Symmetric Encryption**: AES-GCM for authenticated encryption of file content.
-   **Message Authentication**: HMAC-SHA256 for ensuring ciphertext integrity.
-   **Asymmetric Cryptography**: RSA or Elliptic Curve cryptography for key exchange (encrypting file keys for sharing).
-   **Digital Signatures**: RSA-PSS or ECDSA for signing invitations and ensuring authenticity.
-   **Password Hashing**: Argon2 for deriving keys from user passwords and protecting against brute-force attacks.
-   **Randomness**: `crypto/rand` for generating random keys and initialization vectors (IVs).

---

## How to Run and Test

### Prerequisites
-   Go (version 1.13 or later recommended).
-   A correctly configured Go workspace.

### 1. Start the Server
Before running the client or tests, the datastore and keystore servers must be running.

```bash
# From the project's root directory
go run main.go
```
2. Run the Test Suite
All functionality is validated through a comprehensive test suite. Open a new terminal window and run the tests.

Run all tests with verbose output:

```Bash

go test -v
```
Run a specific test:
To debug a specific part of the functionality, you can run a single test. For example, to only run tests related to StoreFile:

```Bash

go test -v -run TestStoreFile
```
Run with race condition detection:

```Bash

go test -v -race
```
