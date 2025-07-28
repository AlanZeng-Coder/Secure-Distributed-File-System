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
	Username     string
	userUUID     uuid.UUID
	masterKey    []byte
	masterEncKey []byte
	publicKey    userlib.PKEEncKey
	verifyKey    userlib.DSVerifyKey
	SignKey      userlib.DSSignKey
	PrivateKey   userlib.PKEDecKey

	fileMapKey []byte

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type FileMap struct {
	FileMetaDataUUID uuid.UUID
	OwnerName        string
	FileMetakey      []byte
}
type FileMetaData struct {
	OwnerUserName       string
	FileBlockHeaderUUID uuid.UUID
	FileBlockKey        []byte
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
	// get the user and put it to userdata
	var userdata User
	userdata.Username = username
	//create master key and enc key for userUUID
	userdata.masterKey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	masterEncKey, _ := userlib.HashKDF(userdata.masterKey, []byte("user"))
	userdata.masterEncKey = masterEncKey[:16]
	//create all keys that I need.
	userdata.publicKey, userdata.PrivateKey, _ = userlib.PKEKeyGen()
	userdata.SignKey, userdata.verifyKey, _ = userlib.DSKeyGen()
	//put public and verify key to the keyStore
	userlib.KeystoreSet(username+"public key", userdata.publicKey)
	userlib.KeystoreSet(username+"verify key", userdata.verifyKey)
	//get the UUID for use
	userdata.userUUID, _ = uuid.FromBytes(userlib.Hash([]byte(userdata.Username)))
	//Marshal the userdata object
	userdatabytes, _ := json.Marshal(userdata)
	//encry userdata json
	ciphertext := userlib.SymEnc(userdata.masterEncKey, userlib.RandomBytes(16), userdatabytes)
	//sig it
	sig, _ := userlib.DSSign(userdata.SignKey, ciphertext)
	//Store it to dataStore
	// for userUUID, the first 256 bytes is sig.
	userlib.DatastoreSet(userdata.userUUID, append(sig, ciphertext...))

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	// find UUID based on username
	targetUUID, _ := uuid.FromBytes(userlib.Hash([]byte(username)))
	// get value from the UUID
	bytes, _ := userlib.DatastoreGet(targetUUID)
	// sperate the sig and content from bytes
	sig := bytes[0:256]
	encJsonBytes := bytes[256:]
	//get verify key from Keystore
	verifyKey, _ := userlib.KeystoreGet(username + "verify key")
	// verifty the value, make sure no attack
	err = userlib.DSVerify(verifyKey, encJsonBytes, sig)
	if err != nil {
		return nil, err
	}

	//get the master key and master enc key
	masterKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	masterEncKey, _ := userlib.HashKDF(masterKey, []byte("user"))
	masterEncKey = masterEncKey[:16]
	//decry the ciperjsonbytes and get the json
	jsonBytes := userlib.SymDec(masterEncKey, encJsonBytes)
	// transfer json to interface, now we have usedata object
	err = json.Unmarshal(jsonBytes, &userdata)
	if err != nil {
		return nil, err
	}
	// giving all the variable back to userdata
	userdata.userUUID = targetUUID
	userdata.masterKey = masterKey
	userdata.masterEncKey = masterEncKey
	userdata.verifyKey = verifyKey
	//get the public key
	publicKey, _ := userlib.KeystoreGet(username + "public key")
	// giving value back to userdata
	userdata.publicKey = publicKey
	//make a pointer for single client device
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// get the exactly UUID for the fileName and user
	fileUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	//initial FileMap fix later here
	var fileMap FileMap
	fileMap.OwnerName = userdata.Username

	fileBlockHeaderUUID := uuid.New()
	fileMap.FileMetaDataUUID = fileBlockHeaderUUID
	fileBlockKey, _ := userlib.HashKDF(userdata.masterKey, []byte("fileBlockHeader"))
	fileBlockKey = fileBlockKey[:16]
	fileMap.FileMetakey = fileBlockKey

	//create fileMapKey and ready to encry fileMap
	fileMapKey, _ := userlib.HashKDF(userdata.masterKey, []byte("fileMap"))
	fileMapKey = fileMapKey[0:16]

	fileMapjson, _ := json.Marshal(fileMap)
	ciphertext := userlib.SymEnc(fileMapKey, userlib.RandomBytes(16), fileMapjson)
	hmac, _ := userlib.HMACEval(fileMapKey, ciphertext)
	//64 bytes hamc
	fileMapBytes := append(hmac, ciphertext...)

	//store fileMapBytes to datastore
	userlib.DatastoreSet(fileUUID, fileMapBytes)

	//initial FileBlockHeader
	var fileBlockHeader FileBlockHeader
	fileContentKey, _ := userlib.HashKDF(userdata.masterKey, []byte("fileContent"))
	fileContentKey = fileContentKey[:16]
	fileBlockHeader.FileContentKey = fileContentKey
	firstUUID := uuid.New()
	lastUUID := uuid.New()
	fileBlockHeader.FirstUUID = firstUUID
	fileBlockHeader.LastUUID = lastUUID

	fileBlockHeaderjson, _ := json.Marshal(fileBlockHeader)
	ciphertext = userlib.SymEnc(fileBlockKey, userlib.RandomBytes(16), fileBlockHeaderjson)
	hmac, _ = userlib.HMACEval(fileBlockKey, ciphertext)
	fileBlockHeaderBytes := append(hmac, ciphertext...)

	userlib.DatastoreSet(fileBlockHeaderUUID, fileBlockHeaderBytes)

	//first fileContent
	var firstFileContent FileContent
	firstFileContent.Content = content
	firstFileContent.NextUUID = lastUUID

	firstFileContentjson, _ := json.Marshal(firstFileContent)
	ciphertext = userlib.SymEnc(fileContentKey, userlib.RandomBytes(16), firstFileContentjson)
	hmac, _ = userlib.HMACEval(fileContentKey, ciphertext)
	firstFileContentBytes := append(hmac, ciphertext...)
	userlib.DatastoreSet(firstUUID, firstFileContentBytes)
	// last fileContent
	var lastFileContent FileContent
	lastFileContent.NextUUID = uuid.New()
	lastFileContentjson, _ := json.Marshal(lastFileContent)
	ciphertext = userlib.SymEnc(fileContentKey, userlib.RandomBytes(16), lastFileContentjson)
	hmac, _ = userlib.HMACEval(fileContentKey, ciphertext)
	lastFileContentBytes := append(hmac, ciphertext...)
	userlib.DatastoreSet(lastUUID, lastFileContentBytes)
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
