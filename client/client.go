package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"
	"strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username      string
	UserUUID      uuid.UUID
	masterKey     []byte
	masterEncKey  []byte
	publicKey     userlib.PKEEncKey
	verifyKey     userlib.DSVerifyKey
	SignKey       userlib.DSSignKey
	PrivateKey    userlib.PKEDecKey
	FilesInfoUUID uuid.UUID

	filesInfoKey []byte
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}
type FilesInfo struct {
	Files map[uuid.UUID]bool
}
type FileMap struct {
	FileMetaDataUUID uuid.UUID
	OwnerName        string
	FileMetaKey      []byte
}
type FileMetaData struct {
	Version             int
	OwnerUserName       string
	FileBlockHeaderUUID uuid.UUID
	FileBlockKey        []byte
	SharingTreeUUID     uuid.UUID
	PendingUpdateKey    []byte
	PendingUUID         uuid.UUID
}
type FileBlockHeader struct {
	FirstUUID      uuid.UUID
	LastUUID       uuid.UUID
	FileContentKey []byte
}
type FileContent struct {
	Content  []byte
	NextUUID uuid.UUID
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, fmt.Errorf("User name should not be empty")
	}
	_, ok := userlib.KeystoreGet(username + "public key")
	if ok {
		return nil, fmt.Errorf("User is exist")
	}

	// get the user and put it to userdata
	var userdata User
	userdata.Username = username
	//create master key and enc key for userUUID
	userdata.masterKey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	masterEncKey, err := userlib.HashKDF(userdata.masterKey, []byte("user"))
	if err != nil {
		return nil, err
	}
	userdata.masterEncKey = masterEncKey[:16]
	//create all keys that I need.
	userdata.publicKey, userdata.PrivateKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.SignKey, userdata.verifyKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	//put public and verify key to the keyStore
	userlib.KeystoreSet(username+"public key", userdata.publicKey)
	userlib.KeystoreSet(username+"verify key", userdata.verifyKey)
	//get the UUID for use
	userdata.UserUUID, err = uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	// get the filesInfoUUID and make the filesInfo
	userdata.FilesInfoUUID = uuid.New()
	filesInfoKey, err := userlib.HashKDF(userdata.masterKey, []byte("filesInfo"))
	if err != nil {
		return nil, err
	}
	filesInfoKey = filesInfoKey[0:16]
	var filesInfo FilesInfo
	filesInfo.Files = make(map[uuid.UUID]bool)
	dataJson, err := json.Marshal(filesInfo)
	if err != nil {
		return nil, err
	}
	dataJson = userlib.SymEnc(filesInfoKey, userlib.RandomBytes(16), dataJson)
	hmac, err := userlib.HMACEval(filesInfoKey, dataJson)
	if err != nil {
		return nil, err
	}

	userlib.DatastoreSet(userdata.FilesInfoUUID, append(hmac, dataJson...))
	//Marshal the userdata object
	userdatabytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	//encry userdata json
	ciphertext := userlib.SymEnc(userdata.masterEncKey, userlib.RandomBytes(16), userdatabytes)
	//sig it
	sig, err := userlib.DSSign(userdata.SignKey, ciphertext)
	if err != nil {
		return nil, err
	}
	//Store it to dataStore
	// for userUUID, the first 256 bytes is sig.
	userlib.DatastoreSet(userdata.UserUUID, append(sig, ciphertext...))

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	verifyKey, ok := userlib.KeystoreGet(username + "verify key")
	if !ok {
		return nil, fmt.Errorf("user is not exist")
	}
	var userdata User
	// find UUID based on username
	targetUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	// get value from the UUID
	bytes, ok := userlib.DatastoreGet(targetUUID)
	if !ok {
		return nil, fmt.Errorf("file got delete by attacker")
	}
	if len(bytes) < 256 {
		return nil, fmt.Errorf("got modify")
	}
	// sperate the sig and content from bytes
	sig := bytes[0:256]
	encJsonBytes := bytes[256:]
	//get verify key from Keystore

	// verifty the value, make sure no attack
	err = userlib.DSVerify(verifyKey, encJsonBytes, sig)
	if err != nil {
		return nil, fmt.Errorf("got modift")
	}

	//get the master key and master enc key
	masterKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	masterEncKey, err := userlib.HashKDF(masterKey, []byte("user"))
	if err != nil {
		return nil, err
	}
	masterEncKey = masterEncKey[:16]
	//decry the ciperjsonbytes and get the json
	jsonBytes := userlib.SymDec(masterEncKey, encJsonBytes)
	// transfer json to interface, now we have usedata object
	err = json.Unmarshal(jsonBytes, &userdata)
	if err != nil {
		return nil, fmt.Errorf("password is wrong")
	}
	// giving all the variable back to userdata
	userdata.masterKey = masterKey
	userdata.masterEncKey = masterEncKey
	userdata.verifyKey = verifyKey
	//get the public key
	publicKey, ok := userlib.KeystoreGet(username + "public key")
	if !ok {
		return nil, fmt.Errorf("there is no this kind of public key")
	}
	userdata.publicKey = publicKey
	// get the verifyKey
	verifyKey, ok = userlib.KeystoreGet(username + "verify key")
	if !ok {
		return nil, fmt.Errorf("there is no this kind of public key")
	}
	userdata.verifyKey = verifyKey

	// get the filesInfoKey
	filesInfoKey, err := userlib.HashKDF(masterKey, []byte("filesInfo"))
	if err != nil {
		return nil, fmt.Errorf("cannot make the filesInfoKey")
	}
	userdata.filesInfoKey = filesInfoKey

	//make a pointer for single client device
	userdataptr = &userdata
	return userdataptr, nil
}

// GetFilesInfo retrieves the FilesInfo from Datastore.
func (userdata *User) GetFilesInfo() (*FilesInfo, error) {
	filesInfoKey, err := userlib.HashKDF(userdata.masterKey, []byte("filesInfo"))
	if err != nil {
		return nil, fmt.Errorf("failed to generate filesInfoKey: %v", err)
	}
	filesInfoKey = filesInfoKey[:16]

	dataJson, ok := userlib.DatastoreGet(userdata.FilesInfoUUID)
	if !ok {
		return nil, errors.New("filesInfo not found")
	}
	if len(dataJson) < 64 {
		return nil, errors.New("filesInfo got modify")
	}
	// Verify HMAC
	hmac := dataJson[:64]
	dataJson = dataJson[64:]
	computedHmac, err := userlib.HMACEval(filesInfoKey, dataJson)
	if err != nil {
		return nil, fmt.Errorf("failed to compute HMAC for FilesInfo: %v", err)
	}
	if !userlib.HMACEqual(hmac, computedHmac) {
		return nil, errors.New("filesInfo got modified")
	}

	// Decrypt and unmarshal
	plaintext := userlib.SymDec(filesInfoKey, dataJson)
	var filesInfo FilesInfo
	if err := json.Unmarshal(plaintext, &filesInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal FilesInfo: %v", err)
	}
	if filesInfo.Files == nil {
		filesInfo.Files = make(map[uuid.UUID]bool)
	}
	return &filesInfo, nil
}

// SetFilesInfo stores the FilesInfo to Datastore with encryption and HMAC.
func (userdata *User) SetFilesInfo(filesInfo *FilesInfo) error {
	if filesInfo == nil {
		return errors.New("filesInfo is nil")
	}

	filesInfoKey, err := userlib.HashKDF(userdata.masterKey, []byte("filesInfo"))
	if err != nil {
		return fmt.Errorf("failed to generate filesInfoKey: %v", err)
	}
	filesInfoKey = filesInfoKey[:16]

	// marshal filesInfo
	jsonBytes, err := json.Marshal(filesInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal FilesInfo: %v", err)
	}

	// Encrypt and HMAC
	ciphertext := userlib.SymEnc(filesInfoKey, userlib.RandomBytes(16), jsonBytes)
	hmac, err := userlib.HMACEval(filesInfoKey, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to compute HMAC for FilesInfo: %v", err)
	}

	// Store
	userlib.DatastoreSet(userdata.FilesInfoUUID, append(hmac, ciphertext...))
	return nil
}

func (userdata *User) SetFileMap(fileMap *FileMap, fileMapUUID uuid.UUID, fileMapKey []byte) error {
	if fileMap == nil {
		return errors.New("fileMap is nil")
	}

	// marshal FileMap
	fileMapJson, err := json.Marshal(fileMap)
	if err != nil {
		return fmt.Errorf("failed to marshal FileMap: %v", err)
	}

	// Encrypt and compute HMAC
	ciphertext := userlib.SymEnc(fileMapKey, userlib.RandomBytes(16), fileMapJson)
	hmac, err := userlib.HMACEval(fileMapKey, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to compute HMAC for FileMap: %v", err)
	}

	// Store to Datastore
	fileMapBytes := append(hmac, ciphertext...)
	userlib.DatastoreSet(fileMapUUID, fileMapBytes)
	return nil
}

func (userdata *User) SetFileMetaData(fileMetaData *FileMetaData, fileMetaDataUUID uuid.UUID, fileMetaKey []byte) error {
	if fileMetaData == nil {
		return errors.New("fileMetaData is nil")
	}

	// marshal FileMetaData
	fileMetaDataJson, err := json.Marshal(fileMetaData)
	if err != nil {
		return fmt.Errorf("failed to marshal FileMetaData: %v", err)
	}

	// Encrypt and sign
	fileMetaDataJson = userlib.SymEnc(fileMetaKey, userlib.RandomBytes(16), fileMetaDataJson)
	sig, err := userlib.DSSign(userdata.SignKey, fileMetaDataJson)
	if err != nil {
		return fmt.Errorf("failed to sign FileMetaData: %v", err)
	}

	// Store to Datastore
	userlib.DatastoreSet(fileMetaDataUUID, append(sig, fileMetaDataJson...))
	return nil
}

func (userdata *User) SetFileBlockHeader(fileBlockHeader *FileBlockHeader, fileBlockHeaderUUID uuid.UUID, fileBlockKey []byte) error {
	if fileBlockHeader == nil {
		return errors.New("fileBlockHeader is nil")
	}

	// marshal FileBlockHeader
	fileBlockHeaderJson, err := json.Marshal(fileBlockHeader)
	if err != nil {
		return fmt.Errorf("failed to marshal FileBlockHeader: %v", err)
	}

	// Encrypt and compute HMAC
	ciphertext := userlib.SymEnc(fileBlockKey, userlib.RandomBytes(16), fileBlockHeaderJson)
	hmac, err := userlib.HMACEval(fileBlockKey, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to compute HMAC for FileBlockHeader: %v", err)
	}

	// Store to Datastore
	fileBlockHeaderBytes := append(hmac, ciphertext...)
	userlib.DatastoreSet(fileBlockHeaderUUID, fileBlockHeaderBytes)
	return nil
}

func (userdata *User) SetFileContent(fileContent *FileContent, contentUUID uuid.UUID, fileContentKey []byte) error {
	if fileContent == nil {
		return errors.New("fileContent is nil")
	}

	// marshal FileContent
	fileContentJson, err := json.Marshal(fileContent)
	if err != nil {
		return fmt.Errorf("failed to marshal FileContent: %v", err)
	}

	// Encrypt and compute HMAC
	ciphertext := userlib.SymEnc(fileContentKey, userlib.RandomBytes(16), fileContentJson)
	hmac, err := userlib.HMACEval(fileContentKey, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to compute HMAC for FileContent: %v", err)
	}

	// Store to Datastore
	fileContentBytes := append(hmac, ciphertext...)
	userlib.DatastoreSet(contentUUID, fileContentBytes)
	return nil
}

func (userdata *User) SetSharingTree(sharingTree *SharingTree, sharingTreeUUID uuid.UUID, sharingTreeKey []byte) error {
	if sharingTree == nil {
		return errors.New("sharingTree is nil")
	}

	// marshal SharingTree
	jsonBytes, err := json.Marshal(sharingTree)
	if err != nil {
		return fmt.Errorf("failed to marshal SharingTree: %v", err)
	}

	// Encrypt and compute HMAC
	ciphertext := userlib.SymEnc(sharingTreeKey, userlib.RandomBytes(16), jsonBytes)
	hmac, err := userlib.HMACEval(sharingTreeKey, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to compute HMAC for SharingTree: %v", err)
	}

	// Store to Datastore
	userlib.DatastoreSet(sharingTreeUUID, append(hmac, ciphertext...))
	return nil
}

func (userdata *User) SetPendingUpdate(pendingUpdate *PendingUpdate, pendingUUID uuid.UUID, pendingUpdateKey []byte) error {
	if pendingUpdate == nil {
		return errors.New("pendingUpdate is nil")
	}

	// marshal PendingUpdate
	jsonBytes, err := json.Marshal(pendingUpdate)
	if err != nil {
		return fmt.Errorf("failed to marshal PendingUpdate: %v", err)
	}

	// Encrypt and compute HMAC
	ciphertext := userlib.SymEnc(pendingUpdateKey, userlib.RandomBytes(16), jsonBytes)
	hmac, err := userlib.HMACEval(pendingUpdateKey, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to compute HMAC for PendingUpdate: %v", err)
	}

	// Store to Datastore
	userlib.DatastoreSet(pendingUUID, append(hmac, ciphertext...))
	return nil
}

func (userdata *User) GetFileContent(contentUUID uuid.UUID, fileContentKey []byte) (*FileContent, error) {
	// get FileContent data
	dataJson, ok := userlib.DatastoreGet(contentUUID)
	if !ok {
		return nil, errors.New("file content not found")
	}
	if len(dataJson) < 64 {
		return nil, fmt.Errorf("fileContent got modify")
	}
	// Verify HMAC
	hmac := dataJson[0:64]
	dataJson = dataJson[64:]
	computerHmac, err := userlib.HMACEval(fileContentKey, dataJson)
	if err != nil {
		return nil, fmt.Errorf("failed to compute HMAC for FileContent: %v", err)
	}
	if !userlib.HMACEqual(computerHmac, hmac) {
		return nil, errors.New("file content got modified")
	}

	// Decrypt and unmarshal FileContent
	dataJson = userlib.SymDec(fileContentKey, dataJson)
	var fileContent FileContent
	if err := json.Unmarshal(dataJson, &fileContent); err != nil {
		return nil, fmt.Errorf("failed to unmarshal FileContent: %v", err)
	}

	return &fileContent, nil
}

func (userdata *User) GetKeyInfo(fileMetaDataUUID uuid.UUID, ownerName string) (*KeyInfo, error) {
	// Generate targetUUID
	targetUUID, err := uuid.FromBytes(userlib.Hash([]byte(fileMetaDataUUID.String() + userdata.Username))[:16])
	if err != nil {
		return nil, fmt.Errorf("failed to generate targetUUID: %v", err)
	}

	// Get KeyInfo data
	bytes, ok := userlib.DatastoreGet(targetUUID)
	if !ok {
		return nil, errors.New("no new filemetadata key found")
	}

	// Verify signature
	verifyKey, ok := userlib.KeystoreGet(ownerName + "verify key")
	if !ok {
		return nil, errors.New("verification key not found")
	}
	if len(bytes) < 256 {
		return nil, fmt.Errorf("keyinfo got modify")
	}
	sig := bytes[0:256]
	bytes = bytes[256:]
	if err := userlib.DSVerify(verifyKey, bytes, sig); err != nil {
		return nil, fmt.Errorf("keyInfo signature verification failed: %v", err)
	}

	// Decrypt and unmarshal KeyInfo
	dataJson, err := userlib.PKEDec(userdata.PrivateKey, bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt KeyInfo: %v", err)
	}
	var keyInfo KeyInfo
	if err := json.Unmarshal(dataJson, &keyInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal KeyInfo: %v", err)
	}

	return &keyInfo, nil
}

func (userdata *User) GetFileMap(filename string) (*FileMap, error) {
	// Generate fileMap UUID
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + " " + userdata.Username + " "))[:16])
	if err != nil {
		return nil, err
	}

	// Find fileMap data
	dataJson, ok := userlib.DatastoreGet(fileMapUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	if len(dataJson) < 64 {
		return nil, fmt.Errorf("fileMap got modify")
	}
	// Verify HMAC
	hmac := dataJson[0:64]
	dataJson = dataJson[64:]
	fileMapKey, err := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
	if err != nil {
		return nil, err
	}
	fileMapKey = fileMapKey[:16]
	computerHmac, err := userlib.HMACEval(fileMapKey, dataJson)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(computerHmac, hmac) {
		return nil, errors.New("file map got modified")
	}

	// Decrypt and unmarshal FileMap
	var fileMap FileMap
	dataJson = userlib.SymDec(fileMapKey, dataJson)
	if err := json.Unmarshal(dataJson, &fileMap); err != nil {
		return nil, fmt.Errorf("fileMapKey is wrong")
	}
	return &fileMap, nil
}

// GetFileMetaData retrieves the FileMetaData using the FileMap information.
func (userdata *User) GetFileMetaData(fileMap *FileMap, fileName string) (*FileMetaData, error) {

	//fileMapUUID, _ := uuid.FromBytes(userlib.Hash([]byte(fileName + userdata.Username))[:16])

	//fileMapKey, _ := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+fileName))

	// Get verification key
	verifyKey, ok := userlib.KeystoreGet(fileMap.OwnerName + "verify key")
	if !ok {
		return nil, errors.New("verification key not found")
	}

	// Get fileMeta data
	fileMetaUUID := fileMap.FileMetaDataUUID
	fileMetaKey := fileMap.FileMetaKey
	bytes, ok := userlib.DatastoreGet(fileMetaUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("file metadata not found"))
	}
	if len(bytes) < 256 {
		return nil, fmt.Errorf("fileMetaData got modify")
	}
	// Verify signature
	sig := bytes[0:256]
	bytes = bytes[256:]
	if err := userlib.DSVerify(verifyKey, bytes, sig); err != nil {

		return nil, fmt.Errorf("fileMetaData got mofify")
	}

	// Decrypt and unmarshal FileMetaData
	var fileMetaData FileMetaData
	dataJson := userlib.SymDec(fileMetaKey, bytes)
	if err := json.Unmarshal(dataJson, &fileMetaData); err != nil {
		return nil, fmt.Errorf("cannot unmarshal, the key is wrong")
	}

	return &fileMetaData, nil
}

func (userdata *User) GetFileBlockHeader(fileMetaData *FileMetaData) (*FileBlockHeader, error) {
	// Get fileBlockHeader data
	fileBlockHeaderUUID := fileMetaData.FileBlockHeaderUUID
	fileBlockKey := fileMetaData.FileBlockKey
	dataJson, ok := userlib.DatastoreGet(fileBlockHeaderUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("file block header not found"))
	}
	if len(dataJson) < 64 {
		return nil, fmt.Errorf("fileBlockHeader got modify")
	}
	// Verify HMAC
	hmac := dataJson[0:64]
	dataJson = dataJson[64:]
	computerHmac, err := userlib.HMACEval(fileBlockKey, dataJson)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(computerHmac, hmac) {
		return nil, errors.New("file block header got modified")
	}

	// Decrypt and unmarshal FileBlockHeader
	var fileBlockHeader FileBlockHeader
	dataJson = userlib.SymDec(fileBlockKey, dataJson)
	if err := json.Unmarshal(dataJson, &fileBlockHeader); err != nil {
		return nil, err
	}

	return &fileBlockHeader, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Get the UUID for the filename and user
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + " " + userdata.Username + " "))[:16])
	if err != nil {
		return err
	}

	// Check if file exists
	_, ok := userlib.DatastoreGet(fileMapUUID)
	if !ok {
		//get filesInfo
		var filesInfo *FilesInfo
		filesInfo, err = userdata.GetFilesInfo()
		if err != nil {
			return err
		}
		fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + " " + userdata.Username + " "))[:16])
		if err != nil {
			return err
		}
		// if file exist but right now datastore is empty, attacker delete the infomation
		exist := filesInfo.Files[fileMapUUID]
		if exist {
			return fmt.Errorf("FileMap got delete")
		}
		filesInfo.Files[fileMapUUID] = true
		err = userdata.SetFilesInfo(filesInfo)
		if err != nil {
			return err
		}
		// File does not exist, initialize all structures
		// Initialize FileMetaData
		fileMetaData := &FileMetaData{
			Version:             1,
			OwnerUserName:       userdata.Username,
			FileBlockHeaderUUID: uuid.New(),
			PendingUUID:         uuid.New(),
			SharingTreeUUID:     uuid.New(),
		}
		fileBlockKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(fileMetaData.Version)+"fileBlockHeader"+filename))
		if err != nil {
			return fmt.Errorf("failed to generate fileBlockKey: %v", err)
		}
		fileBlockKey = fileBlockKey[:16]
		fileMetaData.FileBlockKey = fileBlockKey
		pendingUpdateKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(fileMetaData.Version)+"pendingUpdate"+filename))
		if err != nil {
			return fmt.Errorf("failed to generate pendingUpdateKey: %v", err)
		}
		pendingUpdateKey = pendingUpdateKey[:16]
		fileMetaData.PendingUpdateKey = pendingUpdateKey

		// Initialize FileMap
		fileMap := &FileMap{
			OwnerName:        userdata.Username,
			FileMetaDataUUID: uuid.New(),
		}
		fileMetaKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(fileMetaData.Version)+"fileMeta"+filename))
		if err != nil {
			return fmt.Errorf("failed to generate fileMetaKey: %v", err)
		}
		fileMetaKey = fileMetaKey[:16]
		fileMap.FileMetaKey = fileMetaKey

		// Create fileMapKey
		fileMapKey, err := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
		if err != nil {
			return fmt.Errorf("failed to generate fileMapKey: %v", err)
		}
		fileMapKey = fileMapKey[:16]

		// Store FileMap
		if err := userdata.SetFileMap(fileMap, fileMapUUID, fileMapKey); err != nil {
			return err
		}

		// Store FileMetaData
		if err := userdata.SetFileMetaData(fileMetaData, fileMap.FileMetaDataUUID, fileMetaKey); err != nil {
			return err
		}

		// Store PendingUpdate
		pendingUpdate := &PendingUpdate{}
		if err := userdata.SetPendingUpdate(pendingUpdate, fileMetaData.PendingUUID, fileMetaData.PendingUpdateKey); err != nil {
			return err
		}

		// Store SharingTree
		sharingTree := &SharingTree{Tree: make(map[string][]string)}
		sharingTreeKey, err := userlib.HashKDF(userdata.masterKey, []byte("sharingTree"+filename))
		if err != nil {
			return fmt.Errorf("failed to generate sharingTreeKey: %v", err)
		}
		sharingTreeKey = sharingTreeKey[:16]
		if err := userdata.SetSharingTree(sharingTree, fileMetaData.SharingTreeUUID, sharingTreeKey); err != nil {
			return err
		}

		// Initialize FileBlockHeader
		fileBlockHeader := &FileBlockHeader{
			FirstUUID: uuid.New(),
			LastUUID:  uuid.New(),
		}
		fileContentKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(fileMetaData.Version)+"fileContent"+filename))
		if err != nil {
			return fmt.Errorf("failed to generate fileContentKey: %v", err)
		}
		fileContentKey = fileContentKey[:16]
		fileBlockHeader.FileContentKey = fileContentKey

		// Store FileBlockHeader
		if err := userdata.SetFileBlockHeader(fileBlockHeader, fileMetaData.FileBlockHeaderUUID, fileMetaData.FileBlockKey); err != nil {
			return err
		}

		// Store first FileContent
		firstFileContent := &FileContent{
			Content:  content,
			NextUUID: fileBlockHeader.LastUUID,
		}
		if err := userdata.SetFileContent(firstFileContent, fileBlockHeader.FirstUUID, fileBlockHeader.FileContentKey); err != nil {
			return err
		}

		// Store last FileContent (empty)
		lastFileContent := &FileContent{
			NextUUID: uuid.New(),
		}
		if err := userdata.SetFileContent(lastFileContent, fileBlockHeader.LastUUID, fileBlockHeader.FileContentKey); err != nil {
			return err
		}
	} else {
		// File exists, update content
		// Get FileMap
		fileMap, err := userdata.GetFileMap(filename)
		if err != nil {
			return err
		}

		// Get FileMetaData
		fileMetaData, err := userdata.GetFileMetaData(fileMap, filename)
		if err != nil {
			// Try to get updated key from KeyInfo
			keyInfo, keyErr := userdata.GetKeyInfo(fileMap.FileMetaDataUUID, fileMap.OwnerName)
			if keyErr != nil {
				return fmt.Errorf("failed to get FileMetaData and KeyInfo: %v", keyErr)
			}
			// Update FileMap with new FileMetaKey
			fileMap.FileMetaKey = keyInfo.FileMetaKey
			fileMapKey, err := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
			if err != nil {
				return fmt.Errorf("failed to generate fileMapKey: %v", err)
			}
			fileMapKey = fileMapKey[:16]
			if err := userdata.SetFileMap(fileMap, fileMapUUID, fileMapKey); err != nil {
				return fmt.Errorf("failed to update FileMap: %v", err)
			}
			// Retry getting FileMetaData with new key
			fileMetaData, err = userdata.GetFileMetaData(fileMap, filename)
			if err != nil {
				return fmt.Errorf("failed to get FileMetaData after key update: %v", err)
			}
		}

		// Get FileBlockHeader
		fileBlockHeader, err := userdata.GetFileBlockHeader(fileMetaData)
		if err != nil {
			return err
		}

		// Update FileContent at FirstUUID
		fileContent := &FileContent{
			Content:  content,
			NextUUID: fileBlockHeader.LastUUID,
		}
		if err := userdata.SetFileContent(fileContent, fileBlockHeader.FirstUUID, fileBlockHeader.FileContentKey); err != nil {
			return fmt.Errorf("failed to store FileContent: %v", err)
		}
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Get FileMap
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + " " + userdata.Username + " "))[:16])
	if err != nil {
		return err
	}
	fileMap, err := userdata.GetFileMap(filename)
	if err != nil {
		return err
	}

	// Get FileMetaData
	_, err = userdata.GetFileMetaData(fileMap, filename)
	if err != nil {
		// Try to get updated key from KeyInfo

		keyInfo, keyErr := userdata.GetKeyInfo(fileMap.FileMetaDataUUID, fileMap.OwnerName)
		if keyErr != nil {
			return fmt.Errorf("failed to get FileMetaData and KeyInfo: %v", keyErr)
		}
		// Update FileMap with new FileMetaKey
		fileMap.FileMetaKey = keyInfo.FileMetaKey
		fileMapKey, err := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
		if err != nil {
			return err
		}
		fileMapKey = fileMapKey[:16]
		if err := userdata.SetFileMap(fileMap, fileMapUUID, fileMapKey); err != nil {
			return fmt.Errorf("failed to update FileMap: %v", err)
		}
		// Retry getting FileMetaData with new key
		_, err = userdata.GetFileMetaData(fileMap, filename)
		if err != nil {
			return fmt.Errorf("failed to get FileMetaData after key update: %v", err)
		}
	}

	fileMetaData, err := userdata.GetFileMetaData(fileMap, filename)
	if err != nil {
		return fmt.Errorf("should never to this step")
	}
	// Get FileBlockHeader
	fileBlockHeader, err := userdata.GetFileBlockHeader(fileMetaData)
	if err != nil {
		return err
	}

	// Append new content
	fileContentKey := fileBlockHeader.FileContentKey
	lastUUID := fileBlockHeader.LastUUID
	newLastUUID := uuid.New()

	// Update FileBlockHeader with new LastUUID
	fileBlockHeader.LastUUID = newLastUUID
	if err := userdata.SetFileBlockHeader(fileBlockHeader, fileMetaData.FileBlockHeaderUUID, fileMetaData.FileBlockKey); err != nil {
		return fmt.Errorf("failed to update FileBlockHeader: %v", err)
	}

	// Store new FileContent at original LastUUID
	fileContent := &FileContent{
		Content:  content,
		NextUUID: newLastUUID,
	}
	if err := userdata.SetFileContent(fileContent, lastUUID, fileContentKey); err != nil {
		return fmt.Errorf("failed to store new FileContent: %v", err)
	}

	// Store empty FileContent at new LastUUID
	emptyFileContent := &FileContent{
		NextUUID: uuid.New(),
	}
	if err := userdata.SetFileContent(emptyFileContent, newLastUUID, fileContentKey); err != nil {
		return fmt.Errorf("failed to store empty FileContent: %v", err)
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Get FileMap
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + " " + userdata.Username + " "))[:16])
	if err != nil {
		return nil, err
	}
	fileMap, err := userdata.GetFileMap(filename)
	if err != nil {
		return nil, err
	}

	// Get FileMetaData
	fileMetaData, err := userdata.GetFileMetaData(fileMap, filename)
	if err != nil {

		// Try to get updated key from KeyInfo
		keyInfo, keyErr := userdata.GetKeyInfo(fileMap.FileMetaDataUUID, fileMap.OwnerName)
		if keyErr != nil {
			return nil, fmt.Errorf("failed to get FileMetaData and KeyInfo: %v", keyErr)
		}
		// Update FileMap with new FileMetaKey
		fileMap.FileMetaKey = keyInfo.FileMetaKey
		fileMapKey, err := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
		if err != nil {
			return nil, err
		}
		fileMapKey = fileMapKey[:16]
		if err := userdata.SetFileMap(fileMap, fileMapUUID, fileMapKey); err != nil {
			return nil, fmt.Errorf("failed to update FileMap: %v", err)
		}
		// Retry getting FileMetaData with new key
		fileMetaData, err = userdata.GetFileMetaData(fileMap, filename)
		if err != nil {
			return nil, fmt.Errorf("failed to get FileMetaData after key update: %v", err)
		}
	}

	// Get FileBlockHeader
	fileBlockHeader, err := userdata.GetFileBlockHeader(fileMetaData)
	if err != nil {
		return nil, err
	}

	// Get file content
	fileContentKey := fileBlockHeader.FileContentKey
	targetUUID := fileBlockHeader.FirstUUID
	lastUUID := fileBlockHeader.LastUUID

	for targetUUID != lastUUID {
		dataJson, ok := userlib.DatastoreGet(targetUUID)
		if !ok {
			return nil, errors.New(strings.ToTitle("file not found"))
		}

		// Verify HMAC
		hmac := dataJson[0:64]
		dataJson = dataJson[64:]
		computerHmac, err := userlib.HMACEval(fileContentKey, dataJson)
		if err != nil {
			return nil, fmt.Errorf("failed to compute HMAC for FileContent: %v", err)
		}
		if !userlib.HMACEqual(computerHmac, hmac) {
			return nil, errors.New("file content got modified")
		}

		// Decrypt and unmarshal FileContent
		var fileContent FileContent
		dataJson = userlib.SymDec(fileContentKey, dataJson)
		if err := json.Unmarshal(dataJson, &fileContent); err != nil {
			return nil, fmt.Errorf("failed to unmarshal FileContent: %v", err)
		}

		// Append content and move to next UUID
		content = append(content, fileContent.Content...)
		targetUUID = fileContent.NextUUID
	}
	return content, nil
}

type Invitation struct {
	FileMetaDataUUID uuid.UUID
	FileMetaKey      []byte
	FileOwnerName    string
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// Get FileMap
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + " " + userdata.Username + " "))[:16])
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to generate fileMapUUID: %v", err)
	}
	fileMap, err := userdata.GetFileMap(filename)
	if err != nil {
		return uuid.Nil, err
	}

	// Get FileMetaData
	_, err = userdata.GetFileMetaData(fileMap, filename)
	if err != nil {
		// Try to get updated key from KeyInfo
		keyInfo, keyErr := userdata.GetKeyInfo(fileMap.FileMetaDataUUID, fileMap.OwnerName)
		if keyErr != nil {
			return uuid.Nil, fmt.Errorf("failed to get FileMetaData and KeyInfo: %v", keyErr)
		}

		// // Check if I was revoked
		// if string(keyInfo.FileMetaKey) == string(fileMap.FileMetaKey) {
		// 	userlib.DatastoreDelete(fileMapUUID)
		// 	return uuid.Nil, errors.New("user was revoked")
		// }

		// Update FileMap with new FileMetaKey
		fileMap.FileMetaKey = keyInfo.FileMetaKey
		fileMapKey, err := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
		if err != nil {
			return uuid.Nil, fmt.Errorf("failed to generate fileMapKey: %v", err)
		}
		fileMapKey = fileMapKey[:16]
		if err := userdata.SetFileMap(fileMap, fileMapUUID, fileMapKey); err != nil {
			return uuid.Nil, fmt.Errorf("failed to update FileMap: %v", err)
		}

		// Retry getting FileMetaData with new key
		_, err = userdata.GetFileMetaData(fileMap, filename)
		if err != nil {
			return uuid.Nil, fmt.Errorf("user was revoked after key update: %v", err)
		}

	}

	// Create and store Invitation with current FileMetaKey
	invitationUUID := uuid.New()
	invitation := &Invitation{
		FileMetaDataUUID: fileMap.FileMetaDataUUID,
		FileMetaKey:      fileMap.FileMetaKey,
		FileOwnerName:    fileMap.OwnerName,
	}
	if err := userdata.SetInvitation(invitation, invitationUUID, recipientUsername); err != nil {
		return uuid.Nil, fmt.Errorf("failed to store Invitation: %v", err)
	}
	// Get FileMetaData
	fileMetaData, err := userdata.GetFileMetaData(fileMap, filename)
	if err != nil {
		return uuid.Nil, err
	}

	pendingUpdate := &PendingUpdate{}
	if existing, err := userdata.GetPendingUpdate(fileMetaData.PendingUUID, fileMetaData.PendingUpdateKey); err == nil && existing != nil {
		pendingUpdate.Updates = existing.Updates
	}
	pendingUpdate.Updates = append(pendingUpdate.Updates, Updates{
		Giver:     userdata.Username,
		Recipient: recipientUsername,
	})
	if err := userdata.SetPendingUpdate(pendingUpdate, fileMetaData.PendingUUID, fileMetaData.PendingUpdateKey); err != nil {
		return uuid.Nil, err
	}

	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Get Invitation
	invitation, err := userdata.GetInvitation(invitationPtr, senderUsername)
	if err != nil {
		return err
	}

	// Check for the filename existion
	//get filesInfo
	var filesInfo *FilesInfo
	filesInfo, err = userdata.GetFilesInfo()
	if err != nil {
		return err
	}
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + " " + userdata.Username + " "))[:16])
	if err != nil {
		return err
	}
	// if file exist but right now datastore is empty, attacker delete the infomation
	exist := filesInfo.Files[fileMapUUID]
	if exist {
		return fmt.Errorf("filename exist")
	}
	filesInfo.Files[fileMapUUID] = true
	err = userdata.SetFilesInfo(filesInfo)
	if err != nil {
		return err
	}
	// Create and store FileMap
	fileMapUUID, err = uuid.FromBytes(userlib.Hash([]byte(filename + " " + userdata.Username + " "))[:16])
	if err != nil {
		return fmt.Errorf("failed to generate fileMapUUID: %v", err)
	}
	fileMap := &FileMap{
		FileMetaDataUUID: invitation.FileMetaDataUUID,
		FileMetaKey:      invitation.FileMetaKey,
		OwnerName:        invitation.FileOwnerName,
	}
	fileMapKey, err := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
	if err != nil {
		return fmt.Errorf("failed to generate fileMapKey: %v", err)
	}
	fileMapKey = fileMapKey[:16]
	if err := userdata.SetFileMap(fileMap, fileMapUUID, fileMapKey); err != nil {
		return err
	}

	return nil
}

func (userdata *User) SetInvitation(invitation *Invitation, invitationUUID uuid.UUID, recipientUsername string) error {
	if invitation == nil {
		return errors.New("invitation is nil")
	}

	// Get Invitation
	jsonBytes, err := json.Marshal(invitation)
	if err != nil {
		return fmt.Errorf("failed to marshal Invitation: %v", err)
	}

	// Get recipient's public key
	publicKey, ok := userlib.KeystoreGet(recipientUsername + "public key")
	if !ok {
		return fmt.Errorf("recipient public key not found for %s", recipientUsername)
	}

	// Encrypt and sign
	ciphertext, err := userlib.PKEEnc(publicKey, jsonBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt Invitation: %v", err)
	}
	sig, err := userlib.DSSign(userdata.SignKey, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to sign Invitation: %v", err)
	}

	// Store to Datastore
	userlib.DatastoreSet(invitationUUID, append(sig, ciphertext...))
	return nil
}

func (userdata *User) GetPendingUpdate(pendingUUID uuid.UUID, pendingUpdateKey []byte) (*PendingUpdate, error) {
	// Get PendingUpdate data
	jsonBytes, ok := userlib.DatastoreGet(pendingUUID)
	if !ok {
		return nil, errors.New("pending update not found")
	}

	// Verify HMAC
	hmac := jsonBytes[0:64]
	jsonBytes = jsonBytes[64:]
	computerHmac, err := userlib.HMACEval(pendingUpdateKey, jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compute HMAC for PendingUpdate: %v", err)
	}
	if !userlib.HMACEqual(hmac, computerHmac) {
		return nil, errors.New("pending update got modified")
	}

	// Decrypt and unmarshal PendingUpdate
	decryJson := userlib.SymDec(pendingUpdateKey, jsonBytes)
	var pendingUpdate PendingUpdate
	if err := json.Unmarshal(decryJson, &pendingUpdate); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PendingUpdate: %v", err)
	}

	return &pendingUpdate, nil
}

func (userdata *User) GetInvitation(invitationPtr uuid.UUID, senderUsername string) (*Invitation, error) {
	// Get Invitation data
	jsonBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return nil, errors.New("invitation not found")
	}

	// Verify signature
	verifyKey, ok := userlib.KeystoreGet(senderUsername + "verify key")
	if !ok {
		return nil, fmt.Errorf("sender verification key not found for %s", senderUsername)
	}
	sig := jsonBytes[0:256]
	jsonBytes = jsonBytes[256:]
	if err := userlib.DSVerify(verifyKey, jsonBytes, sig); err != nil {
		return nil, fmt.Errorf("invitation signature verification failed: %v", err)
	}

	// Decrypt and unmarshal Invitation
	decryJson, err := userlib.PKEDec(userdata.PrivateKey, jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt Invitation: %v", err)
	}
	var invitation Invitation
	if err := json.Unmarshal(decryJson, &invitation); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Invitation: %v", err)
	}
	return &invitation, nil
}

type Updates struct {
	Giver     string
	Recipient string
}
type PendingUpdate struct {
	Updates []Updates
}
type KeyInfo struct {
	FileMetaKey []byte
}
type SharingTree struct {
	Tree map[string][]string
}

func (userdata *User) GetSharingTree(sharingTreeUUID uuid.UUID, sharingTreeKey []byte) (*SharingTree, error) {
	// get SharingTree data
	dataJSON, ok := userlib.DatastoreGet(sharingTreeUUID)
	if !ok {
		return nil, errors.New("sharingTree not found")
	}
	if len(dataJSON) < 64 {
		return nil, errors.New("sharingTree wrong size")
	}

	// Verify HMAC
	hmac := dataJSON[:64]
	dataJSON = dataJSON[64:]
	computedHmac, err := userlib.HMACEval(sharingTreeKey, dataJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to compute HMAC for SharingTree: %v", err)
	}
	if !userlib.HMACEqual(hmac, computedHmac) {
		return nil, errors.New("sharingTree got modified")
	}

	// Decrypt and unmarshal SharingTree
	plaintext := userlib.SymDec(sharingTreeKey, dataJSON)
	var sharingTree SharingTree
	if err := json.Unmarshal(plaintext, &sharingTree); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SharingTree: %v", err)
	}

	return &sharingTree, nil
}
func (userdata *User) SetKeyInfo(keyInfo *KeyInfo, keyUUID uuid.UUID, recipientUsername string) error {
	if keyInfo == nil {
		return errors.New("keyInfo is nil")
	}

	// Get KeyInfo
	jsonBytes, err := json.Marshal(keyInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal KeyInfo: %v", err)
	}

	// Get recipient's public key
	recipientPublicKey, ok := userlib.KeystoreGet(recipientUsername + "public key")
	if !ok {
		return fmt.Errorf("recipient public key not found for %s", recipientUsername)
	}

	// Encrypt and sign
	ciphertext, err := userlib.PKEEnc(recipientPublicKey, jsonBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt KeyInfo: %v", err)
	}
	sig, err := userlib.DSSign(userdata.SignKey, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to sign KeyInfo: %v", err)
	}

	// Store to Datastore
	userlib.DatastoreSet(keyUUID, append(sig, ciphertext...))
	return nil
}
func (userdata *User) DealPendingUpdates(filename string) error {
	// Get FileMap and FileMetaData
	_, err := uuid.FromBytes(userlib.Hash([]byte(filename + " " + userdata.Username + " "))[:16])
	if err != nil {
		return err
	}
	fileMap, err := userdata.GetFileMap(filename)
	if err != nil {
		return err
	}
	fileMetaData, err := userdata.GetFileMetaData(fileMap, filename)
	if err != nil {
		return err
	}

	// Get PendingUpdate and SharingTree
	pendingUpdate, err := userdata.GetPendingUpdate(fileMetaData.PendingUUID, fileMetaData.PendingUpdateKey)
	if err != nil {
		return err
	}
	sharingTreeKey, err := userlib.HashKDF(userdata.masterKey, []byte("sharingTree"+filename))
	if err != nil {
		return fmt.Errorf("failed to generate sharingTreeKey: %v", err)
	}
	sharingTreeKey = sharingTreeKey[:16]
	sharingTree, err := userdata.GetSharingTree(fileMetaData.SharingTreeUUID, sharingTreeKey)
	if err != nil {
		return err
	}

	// Process Updates and store KeyInfo
	for _, update := range pendingUpdate.Updates {
		// Update SharingTree
		sharingTree.Tree[update.Giver] = append(sharingTree.Tree[update.Giver], update.Recipient)

		// Store KeyInfo
		keyUUID, err := uuid.FromBytes(userlib.Hash([]byte(fileMap.FileMetaDataUUID.String() + update.Recipient))[:16])
		if err != nil {
			return fmt.Errorf("failed to generate keyUUID for %s: %v", update.Recipient, err)
		}
		if err := userdata.SetKeyInfo(&KeyInfo{FileMetaKey: fileMap.FileMetaKey}, keyUUID, update.Recipient); err != nil {
			return fmt.Errorf("failed to store KeyInfo for %s: %v", update.Recipient, err)
		}
	}

	// Clear and store PendingUpdate, then store SharingTree
	pendingUpdate.Updates = nil
	if err := userdata.SetPendingUpdate(pendingUpdate, fileMetaData.PendingUUID, fileMetaData.PendingUpdateKey); err != nil {
		return err
	}
	if err := userdata.SetSharingTree(sharingTree, fileMetaData.SharingTreeUUID, sharingTreeKey); err != nil {
		return err
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	if err := userdata.DealPendingUpdates(filename); err != nil {
		return err
	}

	// Get FileMap
	fileMap, err := userdata.GetFileMap(filename)
	if err != nil {
		return err
	}
	if fileMap.OwnerName != userdata.Username {
		return errors.New("not file owner")
	}

	// Get FileMetaData
	fileMetaData, err := userdata.GetFileMetaData(fileMap, filename)
	if err != nil {
		return err
	}

	// get FileBlockHeader
	fileBlockHeader, err := userdata.GetFileBlockHeader(fileMetaData)
	if err != nil {
		return err
	}

	// get SharingTree
	sharingTreeKey, err := userlib.HashKDF(userdata.masterKey, []byte("sharingTree"+filename))
	if err != nil {
		return err
	}
	sharingTreeKey = sharingTreeKey[:16]
	sharingTree, err := userdata.GetSharingTree(fileMetaData.SharingTreeUUID, sharingTreeKey)
	if err != nil {
		return err
	}
	if sharingTree.Tree == nil {
		sharingTree.Tree = make(map[string][]string)
	}

	// generate new key
	newVersion := fileMetaData.Version + 1
	newFileMetaKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(newVersion)+"fileMeta"+filename))
	if err != nil {
		return err
	}
	newFileMetaKey = newFileMetaKey[0:16]
	newFileBlockKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(newVersion)+"fileBlockHeader"+filename))
	if err != nil {
		return err
	}
	newFileBlockKey = newFileBlockKey[0:16]
	newPendingUpdateKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(newVersion)+"pendingUpdate"+filename))
	if err != nil {
		return err
	}
	newPendingUpdateKey = newPendingUpdateKey[0:16]
	newFileContentKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(newVersion)+"fileContent"+filename))
	if err != nil {
		return err
	}
	newFileContentKey = newFileContentKey[0:16]

	// // kick the revoke user and the children from sharing Tree
	// owner := userdata.Username
	// users, exists := sharingTree.Tree[owner]
	// if !exists {
	// 	return errors.New("owner not found or has no recipients")
	// }
	// var newUsers []string
	// found := false
	// for _, u := range users {
	// 	if u == recipientUsername {
	// 		found = true
	// 		continue
	// 	}
	// 	newUsers = append(newUsers, u)
	// }
	// if !found {
	// 	return errors.New("recipient not found in owner's list")
	// }
	// sharingTree.Tree[owner] = newUsers
	// if len(newUsers) == 0 {
	// 	delete(sharingTree.Tree, owner)
	// }

	// queue := list.New()
	// queue.PushBack(recipientUsername)
	// for queue.Len() > 0 {
	// 	elem := queue.Front()
	// 	username := elem.Value.(string)
	// 	queue.Remove(elem)
	// 	if children, ok := sharingTree.Tree[username]; ok {
	// 		for _, child := range children {
	// 			queue.PushBack(child)
	// 		}
	// 		delete(sharingTree.Tree, username)
	// 	}
	// }

	// kick the revoke user and the children from sharing Tree

	owner := userdata.Username
	users, exists := sharingTree.Tree[owner]
	if !exists {
		return errors.New("owner has no recipients")
	}
	var newUsers []string
	found := false
	for _, u := range users {
		if u != recipientUsername {
			newUsers = append(newUsers, u)
		} else {
			found = true
		}
	}
	if !found {
		return errors.New("only owner can revoke direct recipients")
	}
	sharingTree.Tree[owner] = newUsers
	if len(newUsers) == 0 {
		delete(sharingTree.Tree, owner)
	}

	// Use a slice as a queue for BFS
	queue := []string{recipientUsername}
	for len(queue) > 0 {
		username := queue[0]
		queue = queue[1:]

		if children, ok := sharingTree.Tree[username]; ok {
			queue = append(queue, children...)
			delete(sharingTree.Tree, username)
		}
	}

	// update KeyInfo for remind user
	for _, recipients := range sharingTree.Tree {
		for _, recipient := range recipients {
			keyUUID, err := uuid.FromBytes(userlib.Hash([]byte(fileMap.FileMetaDataUUID.String() + recipient))[:16])
			if err != nil {
				return err
			}
			keyInfo := KeyInfo{FileMetaKey: newFileMetaKey}
			if err := userdata.SetKeyInfo(&keyInfo, keyUUID, recipient); err != nil {
				return err
			}
		}
	}

	// encry fileContent and store in datastore
	oldFirstUUID := fileBlockHeader.FirstUUID
	oldLastUUID := fileBlockHeader.LastUUID
	oldContentKey := fileBlockHeader.FileContentKey
	newFirstUUID := uuid.New()
	newUUID := newFirstUUID
	targetUUID := oldFirstUUID
	userlib.DatastoreDelete(oldLastUUID) // delete oldUUID content, mayb not must

	for targetUUID != oldLastUUID {
		fileContent, err := userdata.GetFileContent(targetUUID, oldContentKey)
		if err != nil {
			return err
		}
		oldUUID := targetUUID
		targetUUID = fileContent.NextUUID
		userlib.DatastoreDelete(oldUUID)

		newNextUUID := uuid.New()
		fileContent.NextUUID = newNextUUID
		if err := userdata.SetFileContent(fileContent, newUUID, newFileContentKey); err != nil {
			return err
		}
		newUUID = newNextUUID
	}

	// add new lastUUID
	emptyContent := &FileContent{}
	if err := userdata.SetFileContent(emptyContent, newUUID, newFileContentKey); err != nil {
		return err
	}

	// update FileBlockHeader
	newBlockHeaderUUID := uuid.New()
	fileBlockHeader.FirstUUID = newFirstUUID
	fileBlockHeader.LastUUID = newUUID
	fileBlockHeader.FileContentKey = newFileContentKey
	if err := userdata.SetFileBlockHeader(fileBlockHeader, newBlockHeaderUUID, newFileBlockKey); err != nil {
		return err
	}

	// update FileMetaData
	fileMetaData.Version = newVersion
	fileMetaData.FileBlockHeaderUUID = newBlockHeaderUUID
	fileMetaData.FileBlockKey = newFileBlockKey
	fileMetaData.PendingUpdateKey = newPendingUpdateKey
	if err := userdata.SetFileMetaData(fileMetaData, fileMap.FileMetaDataUUID, newFileMetaKey); err != nil {
		return err
	}

	// Update FileMap
	fileMap.FileMetaKey = newFileMetaKey
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + " " + userdata.Username + " "))[:16])
	if err != nil {
		return err
	}
	fileMapKey, err := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
	if err != nil {
		return err
	}
	fileMapKey = fileMapKey[0:16]
	if err := userdata.SetFileMap(fileMap, fileMapUUID, fileMapKey); err != nil {
		return err
	}

	// update SharingTree
	if err := userdata.SetSharingTree(sharingTree, fileMetaData.SharingTreeUUID, sharingTreeKey); err != nil {
		return err
	}

	return nil
}
