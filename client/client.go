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
	masterEncKey, _ := userlib.HashKDF(userdata.masterKey, []byte("user"))
	userdata.masterEncKey = masterEncKey[:16]
	//create all keys that I need.
	userdata.publicKey, userdata.PrivateKey, _ = userlib.PKEKeyGen()
	userdata.SignKey, userdata.verifyKey, _ = userlib.DSKeyGen()
	//put public and verify key to the keyStore
	userlib.KeystoreSet(username+"public key", userdata.publicKey)
	userlib.KeystoreSet(username+"verify key", userdata.verifyKey)
	//get the UUID for use
	userdata.userUUID, _ = uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
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
	userdata.userUUID = targetUUID
	userdata.masterKey = masterKey
	userdata.masterEncKey = masterEncKey
	userdata.verifyKey = verifyKey
	//get the public key
	publicKey, ok := userlib.KeystoreGet(username + "public key")
	if !ok {
		return nil, fmt.Errorf("there is no this kind of public key")
	}
	// giving value back to userdata
	userdata.publicKey = publicKey
	//make a pointer for single client device
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// get the exactly UUID for the fileName and user
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(fileMapUUID)
	if !ok {

		//initial FileMetaData
		var fileMetaData FileMetaData
		fileMetaData.Version = 1
		fileMetaData.OwnerUserName = userdata.Username
		fileBlockHeaderUUID := uuid.New()
		fileMetaData.FileBlockHeaderUUID = fileBlockHeaderUUID
		fileBlockKey, _ := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(fileMetaData.Version)+"fileBlockHeader"+filename))
		fileBlockKey = fileBlockKey[0:16]
		fileMetaData.FileBlockKey = fileBlockKey
		pendingUpdateKey, _ := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(fileMetaData.Version)+"pendingUpdate"+filename))
		pendingUpdateKey = pendingUpdateKey[0:16]
		fileMetaData.PendingUpdateKey = pendingUpdateKey
		fileMetaData.PendingUUID = uuid.New()
		fileMetaData.SharingTreeUUID = uuid.New()
		//initial FileMap fix later here
		var fileMap FileMap
		fileMap.OwnerName = userdata.Username

		fileMetaDataUUID := uuid.New()
		fileMap.FileMetaDataUUID = fileMetaDataUUID
		fileMetaKey, _ := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(fileMetaData.Version)+"fileMeta"+filename))
		fileMetaKey = fileMetaKey[:16]
		fileMap.FileMetaKey = fileMetaKey

		//create fileMapKey and ready to encry fileMap
		fileMapKey, _ := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
		fileMapKey = fileMapKey[0:16]
		userdata.fileMapKey = fileMapKey

		fileMapjson, _ := json.Marshal(fileMap)
		ciphertext := userlib.SymEnc(fileMapKey, userlib.RandomBytes(16), fileMapjson)
		hmac, _ := userlib.HMACEval(fileMapKey, ciphertext)
		//64 bytes hamc
		fileMapBytes := append(hmac, ciphertext...)
		//store fileMapBytes to datastore
		userlib.DatastoreSet(fileMapUUID, fileMapBytes)

		//setting down the sharingTree and PendingUpdate and fileMetaData

		fileMetaDataJson, _ := json.Marshal(fileMetaData)
		fileMetaDataJson = userlib.SymEnc(fileMetaKey, userlib.RandomBytes(16), fileMetaDataJson)
		sig, _ := userlib.DSSign(userdata.SignKey, fileMetaDataJson)
		userlib.DatastoreSet(fileMetaDataUUID, append(sig, fileMetaDataJson...))

		// pending update and sharingtree, have to make hamc first
		var pendingUpdate PendingUpdate
		jsonBytes, _ := json.Marshal(pendingUpdate)
		jsonBytes = userlib.SymEnc(pendingUpdateKey, userlib.RandomBytes(16), jsonBytes)
		hmac, _ = userlib.HMACEval(fileMetaData.PendingUpdateKey, jsonBytes)
		userlib.DatastoreSet(fileMetaData.PendingUUID, append(hmac, jsonBytes...))

		var shareingTree SharingTree
		shareingTree.Tree = make(map[string][]string)
		jsonBytes, _ = json.Marshal(shareingTree)
		sharingTreeKey, _ := userlib.HashKDF(userdata.masterKey, []byte("sharingTree"+filename))
		sharingTreeKey = sharingTreeKey[0:16]
		jsonBytes = userlib.SymEnc(sharingTreeKey, userlib.RandomBytes(16), jsonBytes)
		hmac, _ = userlib.HMACEval(sharingTreeKey, jsonBytes)
		userlib.DatastoreSet(fileMetaData.SharingTreeUUID, append(hmac, jsonBytes...))

		//initial FileBlockHeader
		var fileBlockHeader FileBlockHeader
		fileContentKey, _ := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(fileMetaData.Version)+"fileContent"+filename))
		fileContentKey = fileContentKey[0:16]
		fileBlockHeader.FileContentKey = fileContentKey
		firstUUID := uuid.New()
		lastUUID := uuid.New()
		fileBlockHeader.FirstUUID = firstUUID
		fileBlockHeader.LastUUID = lastUUID

		fileBlockHeaderjson, _ := json.Marshal(fileBlockHeader)
		ciphertext = userlib.SymEnc(fileMetaData.FileBlockKey, userlib.RandomBytes(16), fileBlockHeaderjson)
		hmac, _ = userlib.HMACEval(fileMetaData.FileBlockKey, ciphertext)
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
	} else {
		fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
		if err != nil {
			return err
		}
		dataJson, ok := userlib.DatastoreGet(fileMapUUID)
		if !ok {
			return errors.New(strings.ToTitle("file not found"))
		}
		if len(dataJson) < 64 {
			return fmt.Errorf("fileMap got modify")
		}
		hmac := dataJson[0:64]
		dataJson = dataJson[64:]
		fileMapKey, _ := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
		fileMapKey = fileMapKey[0:16]
		computerHmac, _ := userlib.HMACEval(fileMapKey, dataJson)
		equal := userlib.HMACEqual(computerHmac, hmac)
		if !equal {
			return errors.New("file got modify")
		}
		var fileMap FileMap
		dataJson = userlib.SymDec(userdata.fileMapKey, dataJson)
		err = json.Unmarshal(dataJson, &fileMap)
		if err != nil {
			return err
		}
		//get the fileMetaData
		fileMetaUUID := fileMap.FileMetaDataUUID
		fileMetaKey := fileMap.FileMetaKey

		verifyKey, _ := userlib.KeystoreGet(fileMap.OwnerName + "verify key")
		bytes, _ := userlib.DatastoreGet(fileMetaUUID)
		sig := bytes[0:256]
		bytes = bytes[256:]
		err = userlib.DSVerify(verifyKey, bytes, sig)
		if err != nil {
			return err
		}
		var fileMetaData FileMetaData
		dataJson = userlib.SymDec(fileMetaKey, bytes)
		err = json.Unmarshal(dataJson, &fileMetaData)
		if err != nil {
			return err
		}

		//get the fileBlockHeader info
		fileBlockerHeaderUUID := fileMetaData.FileBlockHeaderUUID
		fileBlockKey := fileMetaData.FileBlockKey

		dataJson, ok = userlib.DatastoreGet(fileBlockerHeaderUUID)
		if !ok {
			return errors.New(strings.ToTitle("file not found"))
		}
		hmac = dataJson[0:64]
		dataJson = dataJson[64:]
		computerHmac, _ = userlib.HMACEval(fileBlockKey, dataJson)
		equal = userlib.HMACEqual(computerHmac, hmac)
		if !equal {
			return errors.New("file got modify")
		}
		var fileBlockerHeader FileBlockHeader
		dataJson = userlib.SymDec(fileBlockKey, dataJson)
		err = json.Unmarshal(dataJson, &fileBlockerHeader)
		if err != nil {
			return err
		}
		// get the info we need on fileBlockerHeader
		lastUUID := fileBlockerHeader.LastUUID
		firstUUID := fileBlockerHeader.FirstUUID
		fileContentKey := fileBlockerHeader.FileContentKey
		// fill in filecontent in last UUID

		var fileContent FileContent
		fileContent.Content = content
		fileContent.NextUUID = lastUUID

		fileContentjson, _ := json.Marshal(fileContent)
		ciphertext := userlib.SymEnc(fileContentKey, userlib.RandomBytes(16), fileContentjson)
		hmac, _ = userlib.HMACEval(fileContentKey, ciphertext)
		fileContentBytes := append(hmac, ciphertext...)
		userlib.DatastoreSet(firstUUID, fileContentBytes)
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	dataJson, ok := userlib.DatastoreGet(fileMapUUID)
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	hmac := dataJson[0:64]
	dataJson = dataJson[64:]
	fileMapKey, _ := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
	fileMapKey = fileMapKey[0:16]
	userdata.fileMapKey = fileMapKey
	computerHmac, _ := userlib.HMACEval(userdata.fileMapKey, dataJson)
	equal := userlib.HMACEqual(computerHmac, hmac)
	if !equal {
		return errors.New("fileMap got modify")
	}
	var fileMap FileMap
	dataJson = userlib.SymDec(userdata.fileMapKey, dataJson)
	err = json.Unmarshal(dataJson, &fileMap)
	if err != nil {
		return fmt.Errorf("wrong fileMap")
	}
	//get the fileMetaData
	fileMetaUUID := fileMap.FileMetaDataUUID
	fileMetaKey := fileMap.FileMetaKey
	verifyKey, _ := userlib.KeystoreGet(fileMap.OwnerName + "verify key")
	bytes, _ := userlib.DatastoreGet(fileMetaUUID)
	sig := bytes[0:256]
	bytes = bytes[256:]
	err = userlib.DSVerify(verifyKey, bytes, sig)
	if err != nil {
		return fmt.Errorf("fileMeta got modify")
	}
	var fileMetaData FileMetaData
	dataJson = userlib.SymDec(fileMetaKey, bytes)
	err = json.Unmarshal(dataJson, &fileMetaData)
	if err != nil {
		// maybe you being revoke or owner change key.
		var keyInfo KeyInfo
		// this targetUUID was make by filemetadataUUID and reipientname, after pendingupdate, owner will know which user need to be sent filemetakey.
		targetUUID, _ := uuid.FromBytes(userlib.Hash([]byte(fileMap.FileMetaDataUUID.String() + userdata.Username))[:16])
		bytes, ok = userlib.DatastoreGet(targetUUID)
		if !ok {
			return fmt.Errorf("no new filemetakey can be found")
		}
		sig = bytes[0:256]
		bytes = bytes[256:]
		err = userlib.DSVerify(verifyKey, bytes, sig)
		if err != nil {
			return fmt.Errorf("keyInfo got modify")
		}
		dataJson, _ = userlib.PKEDec(userdata.PrivateKey, bytes)

		err = json.Unmarshal(dataJson, &keyInfo)
		if err != nil {
			return err
		}

		//get the fileMetaData
		fileMetaKey = keyInfo.FileMetaKey
		bytes, _ := userlib.DatastoreGet(fileMetaUUID)
		sig := bytes[0:256]
		bytes = bytes[256:]
		err = userlib.DSVerify(verifyKey, bytes, sig)
		if err != nil {
			return err
		}
		var fileMetaData FileMetaData
		dataJson = userlib.SymDec(fileMetaKey, bytes)
		err = json.Unmarshal(dataJson, &fileMetaData)
		if err != nil {
			// you being revoked for sure
			userlib.DatastoreDelete(fileMapUUID)
			return fmt.Errorf("i was being revoked")
		} else {
			fileMap.FileMetaKey = fileMetaKey
			jsonBytes, _ := json.Marshal(fileMap)
			jsonBytes = userlib.SymEnc(fileMapKey, userlib.RandomBytes(16), jsonBytes)
			hmac, _ := userlib.HMACEval(fileMapKey, jsonBytes)
			userlib.DatastoreSet(fileMapUUID, append(hmac, jsonBytes...))

		}
	}
	//get the fileBlockHeader info
	fileBlockerHeaderUUID := fileMetaData.FileBlockHeaderUUID
	fileBlockKey := fileMetaData.FileBlockKey

	dataJson, ok = userlib.DatastoreGet(fileBlockerHeaderUUID)
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	hmac = dataJson[0:64]
	dataJson = dataJson[64:]
	computerHmac, _ = userlib.HMACEval(fileBlockKey, dataJson)
	equal = userlib.HMACEqual(hmac, computerHmac)
	if !equal {
		return errors.New("file got modify")
	}
	var fileBlockerHeader FileBlockHeader
	dataJson = userlib.SymDec(fileBlockKey, dataJson)
	err = json.Unmarshal(dataJson, &fileBlockerHeader)

	if err != nil {
		return err
	}
	// get the info we need on fileBlockerHeader
	lastUUID := fileBlockerHeader.LastUUID
	fileContentKey := fileBlockerHeader.FileContentKey
	//change the fileBlockerHeader lastUUID
	newLastUUID := uuid.New()
	fileBlockerHeader.LastUUID = newLastUUID
	fileBlockHeaderjson, _ := json.Marshal(fileBlockerHeader)
	ciphertext := userlib.SymEnc(fileBlockKey, userlib.RandomBytes(16), fileBlockHeaderjson)
	hmac, _ = userlib.HMACEval(fileBlockKey, ciphertext)
	fileBlockHeaderBytes := append(hmac, ciphertext...)

	userlib.DatastoreSet(fileBlockerHeaderUUID, fileBlockHeaderBytes)

	// fill in filecontent in last UUID

	var fileContent FileContent
	fileContent.Content = content
	fileContent.NextUUID = newLastUUID

	fileContentjson, _ := json.Marshal(fileContent)
	ciphertext = userlib.SymEnc(fileContentKey, userlib.RandomBytes(16), fileContentjson)
	hmac, _ = userlib.HMACEval(fileContentKey, ciphertext)
	fileContentBytes := append(hmac, ciphertext...)
	userlib.DatastoreSet(lastUUID, fileContentBytes)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//get the fileMap info
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJson, ok := userlib.DatastoreGet(fileMapUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	hmac := dataJson[0:64]
	dataJson = dataJson[64:]
	fileMapKey, _ := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
	fileMapKey = fileMapKey[0:16]
	userdata.fileMapKey = fileMapKey
	computerHmac, _ := userlib.HMACEval(userdata.fileMapKey, dataJson)
	equal := userlib.HMACEqual(computerHmac, hmac)
	if !equal {
		return nil, errors.New("file got modify")
	}

	var fileMap FileMap
	dataJson = userlib.SymDec(userdata.fileMapKey, dataJson)
	err = json.Unmarshal(dataJson, &fileMap)
	if err != nil {
		return nil, err
	}

	//get the fileMetaBlock
	fileMetaUUID := fileMap.FileMetaDataUUID
	fileMetaKey := fileMap.FileMetaKey
	verifyKey, _ := userlib.KeystoreGet(fileMap.OwnerName + "verify key")
	bytes, _ := userlib.DatastoreGet(fileMetaUUID)
	sig := bytes[0:256]
	bytes = bytes[256:]
	err = userlib.DSVerify(verifyKey, bytes, sig)
	if err != nil {
		return nil, err
	}
	var fileMetaData FileMetaData
	dataJson = userlib.SymDec(fileMetaKey, bytes)
	err = json.Unmarshal(dataJson, &fileMetaData)
	if err != nil {
		// you can not marshal, you need to find the new key, or you were be revoked
		var keyInfo KeyInfo
		// this targetUUID was make by filemetadataUUID and reipientname, after pendingupdate, owner will know which user need to be sent filemetakey.
		targetUUID, _ := uuid.FromBytes(userlib.Hash([]byte(fileMap.FileMetaDataUUID.String() + userdata.Username))[:16])
		bytes, ok = userlib.DatastoreGet(targetUUID)
		if !ok {
			return nil, fmt.Errorf("no new filemetakey can be found")
		}
		sig = bytes[0:256]
		bytes = bytes[256:]
		err = userlib.DSVerify(verifyKey, bytes, sig)
		if err != nil {
			return nil, fmt.Errorf("keyInfo got modify")
		}
		dataJson, _ = userlib.PKEDec(userdata.PrivateKey, bytes)

		err = json.Unmarshal(dataJson, &keyInfo)
		if err != nil {
			return nil, nil
		}

		//get the fileMetaData
		fileMetaKey = keyInfo.FileMetaKey
		bytes, _ := userlib.DatastoreGet(fileMetaUUID)
		sig := bytes[0:256]
		bytes = bytes[256:]
		err = userlib.DSVerify(verifyKey, bytes, sig)
		if err != nil {
			return nil, err
		}
		var fileMetaData FileMetaData
		dataJson = userlib.SymDec(fileMetaKey, bytes)
		err = json.Unmarshal(dataJson, &fileMetaData)
		if err != nil {
			// you being revoked for sure
			userlib.DatastoreDelete(fileMapUUID)
			return nil, fmt.Errorf("i was being revoked")
		} else {
			fileMap.FileMetaKey = fileMetaKey
			jsonBytes, _ := json.Marshal(fileMap)
			jsonBytes = userlib.SymEnc(fileMapKey, userlib.RandomBytes(16), jsonBytes)
			hmac, _ := userlib.HMACEval(fileMapKey, jsonBytes)
			userlib.DatastoreSet(fileMapUUID, append(hmac, jsonBytes...))

		}
	}

	//get the fileBlockHeader info
	fileBlockerHeaderUUID := fileMetaData.FileBlockHeaderUUID
	fileBlockKey := fileMetaData.FileBlockKey
	dataJson, ok = userlib.DatastoreGet(fileBlockerHeaderUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}

	hmac = dataJson[0:64]
	dataJson = dataJson[64:]
	computerHmac, _ = userlib.HMACEval(fileBlockKey, dataJson)
	equal = userlib.HMACEqual(computerHmac, hmac)
	if !equal {
		return nil, errors.New("file got modify")
	}
	var fileBlockerHeader FileBlockHeader
	dataJson = userlib.SymDec(fileBlockKey, dataJson)
	err = json.Unmarshal(dataJson, &fileBlockerHeader)
	if err != nil {
		return nil, err
	}
	//get content

	lastUUID := fileBlockerHeader.LastUUID
	targetUUID := fileBlockerHeader.FirstUUID
	fileContentKey := fileBlockerHeader.FileContentKey

	for targetUUID != lastUUID {
		dataJson, ok = userlib.DatastoreGet(targetUUID)
		userlib.DebugMsg("Hello" + string(content))
		if !ok {
			return nil, errors.New(strings.ToTitle("file not found"))
		}
		hmac = dataJson[0:64]
		dataJson = dataJson[64:]
		computerHmac, _ = userlib.HMACEval(fileContentKey, dataJson)
		equal = userlib.HMACEqual(computerHmac, hmac)
		if !equal {
			return nil, errors.New("file got modify")
		}
		var fileContent FileContent
		dataJson = userlib.SymDec(fileContentKey, dataJson)
		err = json.Unmarshal(dataJson, &fileContent)
		if err != nil {
			return nil, err
		}
		content = append(content, fileContent.Content...)
		targetUUID = fileContent.NextUUID
	}
	// get all the content.

	return content, nil
}

type Invitation struct {
	FileMetaDataUUID uuid.UUID
	FileMetaKey      []byte
	FileOwnerName    string
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// get the fileMap info
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return uuid.New(), fmt.Errorf("can not make uuiD")
	}
	dataJson, ok := userlib.DatastoreGet(fileMapUUID)
	if !ok {
		return uuid.New(), errors.New(strings.ToTitle("file not found"))
	}
	hmac := dataJson[0:64]
	dataJson = dataJson[64:]
	fileMapKey, _ := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
	fileMapKey = fileMapKey[0:16]
	computerHmac, _ := userlib.HMACEval(fileMapKey, dataJson)
	equal := userlib.HMACEqual(hmac, computerHmac)

	if !equal {
		return uuid.Nil, errors.New("file got modify")
	}
	var fileMap FileMap
	dataJson = userlib.SymDec(fileMapKey, dataJson)
	err = json.Unmarshal(dataJson, &fileMap)
	if err != nil {
		return uuid.Nil, fmt.Errorf("fileMap got modify")
	}
	//get the fileMetaUUID
	fileMetaUUID := fileMap.FileMetaDataUUID
	fileMetaKey := fileMap.FileMetaKey
	verifyKey, _ := userlib.KeystoreGet(fileMap.OwnerName + "verify key")
	bytes, _ := userlib.DatastoreGet(fileMetaUUID)
	sig := bytes[0:256]
	bytes = bytes[256:]
	err = userlib.DSVerify(verifyKey, bytes, sig)
	if err != nil {
		return uuid.Nil, fmt.Errorf("fileMetaData got modify")
	}
	var fileMetaData FileMetaData
	dataJson = userlib.SymDec(fileMetaKey, bytes)
	err = json.Unmarshal(dataJson, &fileMetaData)
	// if err is not nil, maybe owner change key or may be I was being revoked.
	if err != nil {
		var keyInfo KeyInfo
		// this targetUUID was make by filemetadataUUID and reipientname, after pendingupdate, owner will know which user need to be sent filemetakey.
		targetUUID, _ := uuid.FromBytes(userlib.Hash([]byte(fileMap.FileMetaDataUUID.String() + userdata.Username))[:16])
		bytes, ok = userlib.DatastoreGet(targetUUID)
		if !ok {
			return uuid.Nil, fmt.Errorf("no new filemetakey can be found")
		}
		sig = bytes[0:256]
		bytes = bytes[256:]
		err = userlib.DSVerify(verifyKey, bytes, sig)
		if err != nil {
			return uuid.Nil, fmt.Errorf("keyInfo got modify")
		}
		dataJson, _ = userlib.PKEDec(userdata.PrivateKey, bytes)

		err = json.Unmarshal(dataJson, &keyInfo)
		if err != nil {
			return uuid.Nil, nil
		}
		// see if the key is the same, knowing you are being revoked or not
		if string(keyInfo.FileMetaKey) == string(fileMap.FileMetaKey) {
			userlib.DatastoreDelete(fileMapUUID)
			return uuid.Nil, fmt.Errorf("i guess I was be revoked")
		} else {
			//get the fileMetaUUID
			fileMetaUUID = fileMap.FileMetaDataUUID
			fileMetaKey = fileMap.FileMetaKey
			verifyKey, _ = userlib.KeystoreGet(fileMap.OwnerName + "verify key")
			bytes, _ = userlib.DatastoreGet(fileMetaUUID)
			sig = bytes[0:256]
			bytes = bytes[256:]
			err = userlib.DSVerify(verifyKey, bytes, sig)
			if err != nil {
				return uuid.Nil, fmt.Errorf("fileMetaData got modify")
			}
			var fileMetaData FileMetaData
			dataJson = userlib.SymDec(fileMetaKey, bytes)
			err = json.Unmarshal(dataJson, &fileMetaData)
			// if err is not nil, after change to new key, I was being revoked for sure.
			if err != nil {
				userlib.DatastoreDelete(fileMapUUID)
				return uuid.Nil, fmt.Errorf("i guess i was be revoked")
			}

			fileMap.FileMetaKey = keyInfo.FileMetaKey
			bytes, _ = json.Marshal(fileMap)
			bytes = userlib.SymEnc(fileMapKey, userlib.RandomBytes(16), bytes)
			hmac, _ = userlib.HMACEval(fileMapKey, bytes)
			userlib.DatastoreSet(fileMapUUID, append(hmac, bytes...))

			invitationUUID := uuid.New()
			var invitation Invitation
			invitation.FileMetaDataUUID = fileMap.FileMetaDataUUID
			invitation.FileMetaKey = keyInfo.FileMetaKey
			invitation.FileOwnerName = fileMap.OwnerName
			json, _ := json.Marshal(invitation)
			// get the recipienter public key
			publicKey, _ := userlib.KeystoreGet(recipientUsername + "public key")
			//encry and put on the Datastore
			ciphertext, _ := userlib.PKEEnc(publicKey, json)
			sig, _ = userlib.DSSign(userdata.SignKey, ciphertext)
			userlib.DatastoreSet(invitationUUID, append(sig, ciphertext...))
			return invitationUUID, nil
		}

	} else {
		// create invitation
		invitationUUID := uuid.New()
		var invitation Invitation
		invitation.FileMetaDataUUID = fileMap.FileMetaDataUUID
		invitation.FileMetaKey = fileMap.FileMetaKey
		invitation.FileOwnerName = fileMap.OwnerName
		json, _ := json.Marshal(invitation)

		// get the recipienter public key
		publicKey, _ := userlib.KeystoreGet(recipientUsername + "public key")
		//encry and put on the Datastore
		ciphertext, _ := userlib.PKEEnc(publicKey, json)
		sig, _ = userlib.DSSign(userdata.SignKey, ciphertext)
		userlib.DatastoreSet(invitationUUID, append(sig, ciphertext...))
		return invitationUUID, nil
	}
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// get the invitation from UUID
	jsonBytes, _ := userlib.DatastoreGet(invitationPtr)
	sig := jsonBytes[0:256]
	jsonBytes = jsonBytes[256:]
	verifyKey, _ := userlib.KeystoreGet(senderUsername + "verify key")
	err := userlib.DSVerify(verifyKey, jsonBytes, sig)
	if err != nil {
		return fmt.Errorf("invitation got modify")
	}
	decryJson, _ := userlib.PKEDec(userdata.PrivateKey, jsonBytes)
	var invitation Invitation
	err = json.Unmarshal(decryJson, &invitation)
	if err != nil {
		return err
	}
	// create the fileMap for this shared file
	fileMapUUID, _ := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	var fileMap FileMap
	fileMap.FileMetaDataUUID = invitation.FileMetaDataUUID
	fileMap.FileMetaKey = invitation.FileMetaKey
	fileMap.OwnerName = invitation.FileOwnerName
	jsonBytes, _ = json.Marshal(fileMap)
	fileMapKey, _ := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
	fileMapKey = fileMapKey[0:16]
	userdata.fileMapKey = fileMapKey
	ciphertext := userlib.SymEnc(fileMapKey, userlib.RandomBytes(16), jsonBytes)
	hmac, _ := userlib.HMACEval(fileMapKey, ciphertext)
	userlib.DatastoreSet(fileMapUUID, append(hmac, ciphertext...))

	// get fileMetaDataInfo, ready for pending update UUID
	jsonBytes, ok := userlib.DatastoreGet(fileMap.FileMetaDataUUID)
	if !ok {
		return fmt.Errorf("filemetadata is not exist")
	}

	sig = jsonBytes[0:256]
	jsonBytes = jsonBytes[256:]
	verifyKey, _ = userlib.KeystoreGet(fileMap.OwnerName + "verify key")
	err = userlib.DSVerify(verifyKey, jsonBytes, sig)
	if err != nil {
		return err
	}
	decryJson = userlib.SymDec(fileMap.FileMetaKey, jsonBytes)
	var fileMetaData FileMetaData
	err = json.Unmarshal(decryJson, &fileMetaData)
	if err != nil {
		return err
	}

	//get pendingUUID information
	pendingUUID := fileMetaData.PendingUUID
	jsonBytes, ok = userlib.DatastoreGet(pendingUUID)
	if !ok {
		return fmt.Errorf("filemetadata is not exist")
	}
	hmac = jsonBytes[0:64]
	jsonBytes = jsonBytes[64:]
	computerHmac, _ := userlib.HMACEval(fileMetaData.PendingUpdateKey, jsonBytes)
	equal := userlib.HMACEqual(hmac, computerHmac)

	if !equal {
		return fmt.Errorf("pendingUpdate got modify")
	}

	var pendingUpdate PendingUpdate
	decryJson = userlib.SymDec(fileMetaData.PendingUpdateKey, jsonBytes)
	err = json.Unmarshal(decryJson, &pendingUpdate)
	if err != nil {
		return err
	}

	var updates Updates
	updates.Giver = senderUsername
	updates.Recipient = userdata.Username
	pendingUpdate.Updates = append(pendingUpdate.Updates, updates)
	jsonBytes, _ = json.Marshal(pendingUpdate)
	jsonBytes = userlib.SymEnc(fileMetaData.PendingUpdateKey, userlib.RandomBytes(16), jsonBytes)
	hmac, _ = userlib.HMACEval(fileMetaData.PendingUpdateKey, jsonBytes)
	userlib.DatastoreSet(fileMetaData.PendingUUID, append(hmac, jsonBytes...))
	return nil
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

func (userdata *User) DealPendingUpdates(filename string) error {
	// get fileMap
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	fileMapKey, err := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
	if err != nil {
		return err
	}
	fileMapKey = fileMapKey[:16]
	dataJSON, ok := userlib.DatastoreGet(fileMapUUID)
	if !ok {
		return errors.New("file map does not exist")
	}
	if len(dataJSON) < 64 {
		return errors.New("filemap size not right")
	}
	hmac := dataJSON[:64]
	dataJSON = dataJSON[64:]
	computedHmac, _ := userlib.HMACEval(fileMapKey, dataJSON)
	equal := userlib.HMACEqual(hmac, computedHmac)

	if !equal {
		return errors.New("fileMap got modify")
	}
	plaintext := userlib.SymDec(fileMapKey, dataJSON)
	var fileMap FileMap
	err = json.Unmarshal(plaintext, &fileMap)
	if err != nil {
		return err
	}

	// get FileMetaData
	fileMetaUUID := fileMap.FileMetaDataUUID
	fileMetaKey := fileMap.FileMetaKey
	dataJSON, ok = userlib.DatastoreGet(fileMetaUUID)
	if !ok {
		return errors.New("fileMetaData does not exist")
	}
	if len(dataJSON) < 256 {
		return errors.New("fileDetaData size not right")
	}
	sig := dataJSON[:256]
	dataJSON = dataJSON[256:]
	verifyKey, ok := userlib.KeystoreGet(fileMap.OwnerName + "verify key")
	if !ok {
		return errors.New("owner verify key not found")
	}
	err = userlib.DSVerify(verifyKey, dataJSON, sig)
	if err != nil {
		return errors.New("fileMetaData got modify")
	}
	plaintext = userlib.SymDec(fileMetaKey, dataJSON)
	var fileMetaData FileMetaData
	err = json.Unmarshal(plaintext, &fileMetaData)
	if err != nil {
		return err
	}

	// get PendingUpdate
	pendingUUID := fileMetaData.PendingUUID
	pendingUpdateKey := fileMetaData.PendingUpdateKey
	dataJSON, ok = userlib.DatastoreGet(pendingUUID)
	if !ok {
		return errors.New("pending update not found")
	}
	if len(dataJSON) < 64 {
		return errors.New("pending update wrong size")
	}
	hmac = dataJSON[:64]
	dataJSON = dataJSON[64:]
	computedHmac, _ = userlib.HMACEval(pendingUpdateKey, dataJSON)
	equal = userlib.HMACEqual(hmac, computedHmac)
	if !equal {
		return errors.New("pending update got modify")
	}
	plaintext = userlib.SymDec(pendingUpdateKey, dataJSON)
	var pendingUpdate PendingUpdate
	err = json.Unmarshal(plaintext, &pendingUpdate)
	if err != nil {
		return err
	}

	// get the sharingTree
	sharingTreeUUID := fileMetaData.SharingTreeUUID
	sharingTreeKey, _ := userlib.HashKDF(userdata.masterKey, []byte("sharingTree"+filename))
	sharingTreeKey = sharingTreeKey[0:16]
	dataJSON, ok = userlib.DatastoreGet(sharingTreeUUID)
	if !ok {
		return errors.New("shareingTree not found")
	}
	if len(dataJSON) < 64 {
		return errors.New("shareingTree wrong size")
	}
	hmac = dataJSON[:64]
	dataJSON = dataJSON[64:]
	computedHmac, _ = userlib.HMACEval(sharingTreeKey, dataJSON)
	equal = userlib.HMACEqual(hmac, computedHmac)
	if !equal {
		return errors.New("sharingTree got modify")
	}
	var sharingTree SharingTree
	plaintext = userlib.SymDec(sharingTreeKey, dataJSON)
	err = json.Unmarshal(plaintext, &sharingTree)
	if err != nil {
		return err
	}
	// process sharingTree
	for _, update := range pendingUpdate.Updates {
		// for giver line, adding the recipient was given the giver
		sharingTree.Tree[update.Giver] = append(sharingTree.Tree[update.Giver], update.Recipient)

		// get keyUUID for KeyInfo, made by filemetadataUUID and the recipient name
		keyUUID, err := uuid.FromBytes(userlib.Hash([]byte(fileMetaUUID.String() + update.Recipient))[:16])
		if err != nil {
			return err
		}

		// make KeyInfo
		var keyInfo KeyInfo
		keyInfo.FileMetaKey = fileMetaKey
		keyInfoJSON, err := json.Marshal(keyInfo)
		if err != nil {
			return err
		}

		// enc keyInfo through recipient public key
		recipientPublicKey, ok := userlib.KeystoreGet(update.Recipient + "public key")
		if !ok {
			return errors.New("recipient public key not found")
		}
		ciphertext, err := userlib.PKEEnc(recipientPublicKey, keyInfoJSON)
		if err != nil {
			return err
		}

		// Sign ciphertext
		sig, err := userlib.DSSign(userdata.SignKey, ciphertext)
		if err != nil {
			return err
		}
		// Store at keyUUID
		userlib.DatastoreSet(keyUUID, append(sig, ciphertext...))
	}
	// pending update should go back to only have hmac with no updates
	pendingUpdate.Updates = nil
	pendingJSON, err := json.Marshal(pendingUpdate.Updates)
	if err != nil {
		return err
	}
	ciphertext := userlib.SymEnc(pendingUpdateKey, userlib.RandomBytes(16), pendingJSON)
	hmac, _ = userlib.HMACEval(pendingUpdateKey, ciphertext)
	userlib.DatastoreSet(pendingUUID, append(hmac, ciphertext...))

	// put SharingTree to datastore
	sharingTreeJSON, err := json.Marshal(sharingTree)
	if err != nil {
		return err
	}
	ciphertext = userlib.SymEnc(sharingTreeKey, userlib.RandomBytes(16), sharingTreeJSON)
	hmac, _ = userlib.HMACEval(sharingTreeKey, ciphertext)
	userlib.DatastoreSet(sharingTreeUUID, append(hmac, ciphertext...))

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Call DealPendingUpdates to process pending updates
	err := userdata.DealPendingUpdates(filename)
	if err != nil {
		return err
	}
	// Load FileMap
	fileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	fileMapKey, err := userlib.HashKDF(userdata.masterKey, []byte("fileMap"+filename))
	if err != nil {
		return err
	}
	fileMapKey = fileMapKey[:16]
	userdata.fileMapKey = fileMapKey
	dataJSON, ok := userlib.DatastoreGet(fileMapUUID)
	if !ok {
		return errors.New("file map not found")
	}
	if len(dataJSON) < 64 {
		return errors.New("file map wrong size")
	}
	hmac := dataJSON[:64]
	dataJSON = dataJSON[64:]
	computedHmac, err := userlib.HMACEval(fileMapKey, dataJSON)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(hmac, computedHmac) {
		return errors.New("file map got modify")
	}
	plaintext := userlib.SymDec(fileMapKey, dataJSON)
	var fileMap FileMap
	err = json.Unmarshal(plaintext, &fileMap)
	if err != nil {
		return err
	}
	if fileMap.OwnerName != userdata.Username {
		return errors.New("not file owner")
	}
	// Load FileMetaData
	fileMetaUUID := fileMap.FileMetaDataUUID
	fileMetaKey := fileMap.FileMetaKey
	dataJSON, ok = userlib.DatastoreGet(fileMetaUUID)
	if !ok {
		return errors.New("file metadata not found")
	}
	if len(dataJSON) < 256 {
		return errors.New("file metadata wrong size")
	}
	sig := dataJSON[:256]
	dataJSON = dataJSON[256:]
	verifyKey, ok := userlib.KeystoreGet(fileMap.OwnerName + "verify key")
	if !ok {
		return errors.New("owner verify key not found")
	}
	err = userlib.DSVerify(verifyKey, dataJSON, sig)
	if err != nil {
		return errors.New("file metadata tampered")
	}
	plaintext = userlib.SymDec(fileMetaKey, dataJSON)
	var fileMetaData FileMetaData
	err = json.Unmarshal(plaintext, &fileMetaData)
	if err != nil {
		return err
	}

	//load fileBlockHeader
	fileBlockUUID := fileMetaData.FileBlockHeaderUUID
	fileBlockKey := fileMetaData.FileBlockKey
	dataJSON, ok = userlib.DatastoreGet(fileBlockUUID)
	if !ok {
		return errors.New("file map not found")
	}
	if len(dataJSON) < 64 {
		return errors.New("file map wrong size")
	}
	hmac = dataJSON[:64]
	dataJSON = dataJSON[64:]
	computedHmac, err = userlib.HMACEval(fileBlockKey, dataJSON)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(hmac, computedHmac) {
		return errors.New("file map got modify")
	}
	plaintext = userlib.SymDec(fileBlockKey, dataJSON)
	var fileBlockHeader FileBlockHeader
	err = json.Unmarshal(plaintext, &fileBlockHeader)
	if err != nil {
		return err
	}

	// Load SharingTree
	sharingTreeUUID := fileMetaData.SharingTreeUUID
	sharingTreeKey, err := userlib.HashKDF(userdata.masterKey, []byte("sharingTree"+filename))
	if err != nil {
		return err
	}
	sharingTreeKey = sharingTreeKey[:16]
	dataJSON, ok = userlib.DatastoreGet(sharingTreeUUID)
	if !ok {
		return errors.New("sharing tree not found")
	}
	if len(dataJSON) < 64 {
		return errors.New("sharing tree wrong size")
	}
	hmac = dataJSON[:64]
	dataJSON = dataJSON[64:]
	computedHmac, err = userlib.HMACEval(sharingTreeKey, dataJSON)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(hmac, computedHmac) {
		return errors.New("sharing tree tampered")
	}
	plaintext = userlib.SymDec(sharingTreeKey, dataJSON)
	var sharingTree SharingTree
	err = json.Unmarshal(plaintext, &sharingTree)
	if err != nil {
		return err
	}
	if sharingTree.Tree == nil {
		sharingTree.Tree = make(map[string][]string)
	}
	// Generate New Keys
	newVersion := fileMetaData.Version + 1
	newFileMetaKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(newVersion)+"fileMeta"+filename))
	if err != nil {
		return err
	}
	newFileMetaKey = newFileMetaKey[:16]
	newFileBlockKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(newVersion)+"fileBlockHeader"+filename))
	if err != nil {
		return err
	}
	newFileBlockKey = newFileBlockKey[:16]
	newPendingUpdateKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(newVersion)+"pendingUpdate"+filename))
	if err != nil {
		return err
	}
	newPendingUpdateKey = newPendingUpdateKey[:16]
	newFileContentKey, err := userlib.HashKDF(userdata.masterKey, []byte(strconv.Itoa(newVersion)+"fileConten"+filename))
	if err != nil {
		return err
	}
	newFileContentKey = newFileContentKey[0:16]

	// remove revoke use in sharingTree
	var recurseRemove func(username string)
	recurseRemove = func(username string) {
		if users, exists := sharingTree.Tree[username]; exists {
			for _, recipient := range users {
				recurseRemove(recipient)
			}
			delete(sharingTree.Tree, username)
		}
	}
	recurseRemove(recipientUsername)

	for giver, recipients := range sharingTree.Tree {
		var newRecipients []string
		for _, recipient := range recipients {
			if recipient != recipientUsername {
				newRecipients = append(newRecipients, recipient)
			}
		}
		sharingTree.Tree[giver] = newRecipients
	}

	for _, recipients := range sharingTree.Tree {
		for _, recipient := range recipients {
			keyUUID, err := uuid.FromBytes(userlib.Hash([]byte(fileMetaUUID.String() + recipient))[:16])
			if err != nil {
				return err
			}
			var keyInfo KeyInfo
			keyInfo.FileMetaKey = newFileMetaKey
			keyInfoJSON, err := json.Marshal(keyInfo)
			if err != nil {
				return err
			}
			recipientPublicKey, ok := userlib.KeystoreGet(recipient + "public key")
			if !ok {
				return errors.New("recipient public key not found")
			}
			ciphertext, err := userlib.PKEEnc(recipientPublicKey, keyInfoJSON)
			if err != nil {
				return err
			}
			sig, err := userlib.DSSign(userdata.SignKey, ciphertext)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(keyUUID, append(sig, ciphertext...))
		}
	}

	// update FileContent
	firstUUID := fileBlockHeader.FirstUUID
	newFirstUUID := uuid.New()
	newUUID := newFirstUUID
	targetUUID := firstUUID
	lastUUID := fileBlockHeader.LastUUID
	userlib.DatastoreDelete(lastUUID)
	fileContentKey := fileBlockHeader.FileContentKey
	for targetUUID != lastUUID {
		dataJson, ok := userlib.DatastoreGet(targetUUID)
		if !ok {
			return errors.New(strings.ToTitle("file not found"))
		}
		hmac = dataJson[0:64]
		dataJson = dataJson[64:]
		computerHmac, _ := userlib.HMACEval(fileContentKey, dataJson)
		equal := userlib.HMACEqual(computerHmac, hmac)
		if !equal {
			return errors.New("file got modify")
		}
		var fileContent FileContent
		dataJson = userlib.SymDec(fileContentKey, dataJson)
		err = json.Unmarshal(dataJson, &fileContent)
		if err != nil {
			return fmt.Errorf("cannot unmarshal filecontent")
		}
		oldUUID := targetUUID
		targetUUID = fileContent.NextUUID
		userlib.DatastoreDelete(oldUUID)
		newNextUUID := uuid.New()
		fileContent.NextUUID = newNextUUID
		dataJson, _ = json.Marshal(fileContent)
		ciphertext := userlib.SymEnc(newFileContentKey, userlib.RandomBytes(16), dataJson)
		hmac, _ := userlib.HMACEval(newFileContentKey, ciphertext)
		userlib.DatastoreSet(newUUID, append(hmac, ciphertext...))
		newUUID = newNextUUID
	}

	// finish last filecontent
	var fileContent FileContent
	dataJson, _ := json.Marshal(fileContent)
	ciphertext := userlib.SymEnc(newFileContentKey, userlib.RandomBytes(16), dataJson)
	hmac, _ = userlib.HMACEval(newFileContentKey, ciphertext)
	userlib.DatastoreSet(newUUID, append(hmac, ciphertext...))

	// update FileBlockHeader
	newFileBlockHeaderUUID := uuid.New()
	fileBlockHeader.FirstUUID = newFirstUUID
	fileBlockHeader.LastUUID = newUUID
	fileBlockHeader.FileContentKey = newFileContentKey
	fileBlockHeaderJSON, err := json.Marshal(fileBlockHeader)
	if err != nil {
		return err
	}
	ciphertext = userlib.SymEnc(newFileBlockKey, userlib.RandomBytes(16), fileBlockHeaderJSON)
	hmac, _ = userlib.HMACEval(newFileBlockKey, ciphertext)
	userlib.DatastoreSet(newFileBlockHeaderUUID, append(hmac, ciphertext...))

	// update FileMetaData sharingtreeUUID 和 pendingUUID没改，可以考虑更改的
	fileMetaData.Version = newVersion
	fileMetaData.FileBlockHeaderUUID = newFileBlockHeaderUUID
	fileMetaData.FileBlockKey = newFileBlockKey
	fileMetaData.PendingUpdateKey = newPendingUpdateKey
	fileMetaDataJSON, err := json.Marshal(fileMetaData)
	if err != nil {
		return err
	}
	ciphertext = userlib.SymEnc(newFileMetaKey, userlib.RandomBytes(16), fileMetaDataJSON)
	sig, err = userlib.DSSign(userdata.SignKey, ciphertext)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileMetaUUID, append(sig, ciphertext...))

	// update FileMap
	fileMap.FileMetaKey = newFileMetaKey
	fileMapJSON, err := json.Marshal(fileMap)
	if err != nil {
		return err
	}
	ciphertext = userlib.SymEnc(fileMapKey, userlib.RandomBytes(16), fileMapJSON)
	hmac, _ = userlib.HMACEval(fileMapKey, ciphertext)
	userlib.DatastoreSet(fileMapUUID, append(hmac, ciphertext...))

	// Update SharingTree
	sharingTreeJSON, err := json.Marshal(sharingTree)
	if err != nil {
		return err
	}
	ciphertext = userlib.SymEnc(sharingTreeKey, userlib.RandomBytes(16), sharingTreeJSON)
	hmac, _ = userlib.HMACEval(sharingTreeKey, ciphertext)
	userlib.DatastoreSet(sharingTreeUUID, append(hmac, ciphertext...))

	return nil
}
