package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	//var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	//dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("My Tests", func() {

		Context("User Authentication and Edge Cases", func() {
			Specify("Attempt to initialize a user with an existing username.", func() {
				userlib.DebugMsg("Initializing user Alice.")
				_, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Attempting to initialize Alice again with a different password.")
				_, err = client.InitUser("alice", "new_password")
				Expect(err).ToNot(BeNil())
			})

			Specify("Attempt to initialize a user with an empty username.", func() {
				userlib.DebugMsg("Attempting to initialize a user with an empty username.")
				_, err = client.InitUser("", defaultPassword)
				Expect(err).ToNot(BeNil())
			})

			Specify("Attempt to get a user with an incorrect password.", func() {
				userlib.DebugMsg("Initializing user Alice.")
				_, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Attempting to get Alice with the wrong password.")
				_, err = client.GetUser("alice", "wrong_password")
				Expect(err).ToNot(BeNil())
			})

			Specify("Attempt to get a non-existent user.", func() {
				userlib.DebugMsg("Attempting to get a user that has not been initialized.")
				_, err = client.GetUser("nonexistent", defaultPassword)
				Expect(err).ToNot(BeNil())
			})

			Specify("Attempt to get a user with an modify attack.", func() {
				userlib.DebugMsg("Initializing user Alice.")
				_, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Attempting to get a user with an modify attack.")
				userlib.DebugMsg("Attacker modify you datastore under userUUID")
				userUUID, _ := uuid.FromBytes(userlib.Hash([]byte("alice"))[:16])
				userlib.DatastoreSet(userUUID, []byte("modifyit"))
				_, err = client.GetUser("alice", defaultPassword)
				Expect(err).ToNot(BeNil())
			})

			Specify("Attempt to reinitialize a user with an delete attack.", func() {
				userlib.DebugMsg("reInitializing user Alice.")
				_, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Attempting to irenitialize a user with an delete attack.")
				userlib.DebugMsg("Attacker delete all the datastore info")
				userlib.DatastoreClear()
				_, err = client.InitUser("alice", defaultPassword)
				Expect(err).ToNot(BeNil())
			})

			Specify("Attempt to get a user with an delete attack.", func() {
				userlib.DebugMsg("reInitializing user Alice.")
				_, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Attempting to irenitialize a user with an delete attack.")
				userlib.DebugMsg("Attacker delete all the datastore info")
				userlib.DatastoreClear()
				_, err = client.GetUser("alice", defaultPassword)
				Expect(err).ToNot(BeNil())
			})
		})

		Context("File Operations and Edge Cases", func() {
			BeforeEach(func() {
				// Initialize a user for the tests in this context
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())
			})

			Specify("StoreFile should overwrite an existing file's content.", func() {
				userlib.DebugMsg("Alice storing file with initial content.")
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice overwriting the file with new content.")
				err = alice.StoreFile(aliceFile, []byte(contentThree))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Loading the file to check if it was overwritten.")
				data, err := alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentThree)))
			})

			Specify("Attempt to load a non-existent file.", func() {
				userlib.DebugMsg("Alice attempting to load a file that doesn't exist.")
				_, err = alice.LoadFile("nonexistent.txt")
				Expect(err).ToNot(BeNil())
			})

			Specify("Attempt to append to a non-existent file.", func() {
				userlib.DebugMsg("Alice attempting to append to a file that doesn't exist.")
				err = alice.AppendToFile("nonexistent.txt", []byte(contentOne))
				Expect(err).ToNot(BeNil())
			})

			Specify("Storing a file with an empty filename should fail.", func() {
				userlib.DebugMsg("Alice attempting to store a file with an empty filename.")
				err = alice.StoreFile("", []byte(contentOne))
				Expect(err).ToNot(BeNil())
			})

			Specify("Appending empty content to a file should not change it.", func() {
				userlib.DebugMsg("Alice storing a file.")
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice appending empty content.")
				err = alice.AppendToFile(aliceFile, []byte(""))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Loading the file to ensure content is unchanged.")
				data, err := alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Alice appending empty content again.")
				err = alice.AppendToFile(aliceFile, []byte(""))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Loading the file to ensure content is unchanged again.")
				data, err = alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))
			})

			Specify("StoreFile should return not nil under delete attack.", func() {
				userlib.DebugMsg("Alice storing file with initial content.")
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Attacker delete the datastore")
				userlib.DatastoreClear()
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).ToNot(BeNil())
			})

			Specify("StoreFile should return not nil under modify attack.", func() {
				userlib.DebugMsg("Alice storing file with initial content.")
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Attacker modify the datastore")
				fileMapUUID, _ := uuid.FromBytes(userlib.Hash([]byte(aliceFile + "alice"))[:16])
				userlib.DatastoreSet(fileMapUUID, []byte("modifyit"))
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).ToNot(BeNil())
			})

			Specify("Different Device should load the content with same file", func() {
				userlib.DebugMsg("Alice storing file with initial content.")
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Getting user Alice(aliceLaptop).")
				aliceLaptop, err = client.GetUser("alice", defaultPassword)
				Expect(err).To(BeNil())
				userlib.DebugMsg("AliceLaptop loading the file")
				data, err := aliceLaptop.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))
			})

			Specify("Different Device should append the content with same file", func() {
				userlib.DebugMsg("Alice storing file with initial content.")
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Getting user Alice(aliceLaptop).")
				aliceLaptop, err = client.GetUser("alice", defaultPassword)
				Expect(err).To(BeNil())
				userlib.DebugMsg("AliceLaptop loading the file")
				data, err := aliceLaptop.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Getting user Alice(aliceLaptop).")
				aliceLaptop, err = client.GetUser("alice", defaultPassword)
				Expect(err).To(BeNil())
				userlib.DebugMsg("AliceLaptop append the file")
				err = aliceLaptop.AppendToFile(aliceFile, []byte(contentTwo))
				Expect(err).To(BeNil())
				userlib.DebugMsg("Alice loading the file")
				data, err = alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne + contentTwo)))
			})
		})

		Context("Sharing, Revocation, and Access Control", func() {
			BeforeEach(func() {
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())
				bob, err = client.InitUser("bob", defaultPassword)
				Expect(err).To(BeNil())
				charles, err = client.InitUser("charles", defaultPassword)
				Expect(err).To(BeNil())
				//doris, err := client.InitUser("doris", defaultPassword)
				//Expect(err).To(BeNil())

				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			Specify("Revoking access from one user should not affect other shared users.", func() {
				inviteBob, _ := alice.CreateInvitation(aliceFile, "bob")
				bob.AcceptInvitation("alice", inviteBob, bobFile)
				inviteCharles, _ := alice.CreateInvitation(aliceFile, "charles")
				charles.AcceptInvitation("alice", inviteCharles, charlesFile)

				userlib.DebugMsg("Alice revokes Bob's access.")
				err = alice.RevokeAccess(aliceFile, "bob")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bob tries to load the file (should fail).")
				_, err = bob.LoadFile(bobFile)
				Expect(err).ToNot(BeNil())

				userlib.DebugMsg("Charles tries to load the file (should succeed).")
				data, err := charles.LoadFile(charlesFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Charles appends to the file.")
				err = charles.AppendToFile(charlesFile, []byte(contentTwo))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice loads the file to see Charles's changes.")
				data, err = alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne + contentTwo)))
			})

			Specify("A non-owner cannot revoke access.", func() {
				userlib.DebugMsg("Alice shares with Bob.")
				invite, err := alice.CreateInvitation(aliceFile, "bob")
				Expect(err).To(BeNil())
				err = bob.AcceptInvitation("alice", invite, bobFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bob attempts to revoke Alice's access (should fail).")
				err = bob.RevokeAccess(bobFile, "alice")
				Expect(err).ToNot(BeNil())
			})

			Specify("Attempt to revoke access from a user who doesn't have it.", func() {
				userlib.DebugMsg("Alice attempts to revoke Charles's access, but the file was never shared with him.")
				err = alice.RevokeAccess(aliceFile, "charles")
				Expect(err).ToNot(BeNil())
			})

			Specify("Accepting an invitation for a filename that already exists should fail.", func() {
				userlib.DebugMsg("Bob creates his own file named 'bobFile.txt'.")
				err = bob.StoreFile(bobFile, []byte("bobs original file"))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice creates an invitation for Bob.")
				invite, err := alice.CreateInvitation(aliceFile, "bob")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bob attempts to accept the invitation using a filename that he already uses.")
				err = bob.AcceptInvitation("alice", invite, bobFile)
				Expect(err).ToNot(BeNil())
			})

		})
	})

})
