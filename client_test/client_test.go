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

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
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
const defaultPassword2 = "password1"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var diffAlice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User
	//var bobLaptop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	iraFile := "iraFile.txt"

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
			_ = diffAlice
			_ = eve
		})

		Specify("more basic username tests.", func() {
			//testing that Alice and alice are different users
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user alice.")
			diffAlice, err = client.InitUser("alice", defaultPassword2)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting lowercase alice with Alice's pass.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Getting user Alice.")
			aliceDesktop, err = client.GetUser("alice", defaultPassword2)
			Expect(err).To(BeNil())
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			//test really long username
			userlib.DebugMsg("Initializing user bob.")
			eve, err = client.InitUser("bobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbob", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.GetUser("bobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbob", defaultPassword)

		})

		Specify("Basic Test: Testing empty username, duplicate username, empty password.", func() {
			//test empty username, duplicate username (inituser, no getuser)
			userlib.DebugMsg("Initializing user .")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			_, err = client.InitUser("bob", "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob.")
			_, err = client.GetUser("bob", "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting user .")
			_, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())

		})



		Specify("Basic Test: Testing GetUser errors.", func() {
			//user hasn't been initialized yet
			userlib.DebugMsg("Getting uninitialized user Alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			//invalid credentials
			userlib.DebugMsg("Initializing user Alice.")
			grace, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice, incorrect password.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword+"i")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting user Alice, incorrect username.")
			aliceLaptop, err = client.GetUser("alice1", defaultPassword)
			Expect(err).ToNot(BeNil())

			//tamper with the user?
			_, _ = grace.LoadFile("foo")

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

		Specify("Basic Test: Testing namespaces.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice stores file: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob stores file: %s", contentThree)
			err = bob.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading alice's file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Loading bob's file...")
			data2, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentThree)))

		})

		Specify("Basic Test: Testing create/accept/revoke.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice stores file: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//bob has bobFile.txt
			userlib.DebugMsg("bob stores file: %s", contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			//should error
			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			//create invite for filename that doesn't exist in alice's namespace
			userlib.DebugMsg("alice creating invite for Bob.")
			invite3, err := alice.CreateInvitation(bobFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("bob accepts faulty invite.")
			err = bob.AcceptInvitation("alice", invite3, bobFile)
			Expect(err).ToNot(BeNil())

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

			//check that alice can't load a randomly named file

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

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
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

			userlib.DebugMsg("Charles creating invite for Doris for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)

			invite, err = charles.CreateInvitation(charlesFile, "doris")
			Expect(err).To(BeNil())

			//doris accepts invite
			err = doris.AcceptInvitation("charles", invite, dorisFile)

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

			userlib.DebugMsg("Checking that Bob/Charles/Doris lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
			err = doris.AppendToFile(dorisFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: Testing Revoke edge cases", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			aliceFile = ""
			bobFile = ""
			dorisFile = ""
			charlesFile = ""
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes a person without access")
			err := alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("alice invites bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			//alice can append nothing
			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = alice.AppendToFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())

		})

		//BEGIN TO MODIFY DATASTORE AND SEE IF OUR CODE CAN CATCH
		//peyrin tips: modify datastore, super deep trees, super shallow trees, confidentiality/integrity checks
		//user datastoregetmap to see everything in datastore and then user datastoreset to tamper with things
		Specify("Basic Test: Testing modified user.", func() {
			//invalid credentials
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			//tamper with alice
			print(userlib.DatastoreGetMap())
			// userbyte := []byte("alice")
			// userHash := userlib.Hash(userbyte)
			// computed_uuid, err := userlib.uuid.FromBytes(userHash[:16])
			//uuid :=
			//userlib.DatastoreSet(0x14004389a10, userlib.Hash([]byte("getfucked")))
			//try to get alice

			//tamper with the user?
			//use other values on the datastore and move them around, like swap a file
			//CHECK TO MAKE SURE THAT IF THE USER MESSES UP THE ORDER OF DATASTORE THEY CANT DECRYPT ANYTHING

		})
		Specify("Basic Test: init user error cases", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Alice again same user error")
			alice, err = client.InitUser("alice", defaultPassword2)
			Expect(err).ToNot(BeNil())

		})
		Specify("Basic Test: get user error cases", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("getting users Alice should be okay")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("getting users Alice with wrong credentials")
			alice, err = client.GetUser("alice", defaultPassword2)
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: load file", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file for Alice with wrong name")
			_, err := alice.LoadFile(iraFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Basic Test: append no content, and long append and load", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appnding to alice file no content")
			err = alice.AppendToFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appnding to alice file with content")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appnding to alice file with content")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appnding to alice file with content")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appnding to alice file with content")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appnding to alice file with content")
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appnding to alice file with content")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appnding to alice file with content")
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appnding to alice file with content")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading long file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree + "" + contentThree + contentThree + contentThree + contentThree + contentOne + contentThree + contentOne + contentThree)))

		})

		//super deep share tree
		Specify("Ultimate revoke, append, and load test", func() {
			userlib.DebugMsg("Initializing users Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Charles")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Doris")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Eve")
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Grace")
			grace, err = client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Frank")
			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("sharing the aliceFile to charles")
			inviteCharles, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("sharing the aliceFile to bob")
			inviteBob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Making sure bob can't accept accept charles invitation")
			err = bob.AcceptInvitation("alice", inviteCharles, "1234.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepts right invitation")
			err = bob.AcceptInvitation("alice", inviteBob, "1234.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepts right invitation")
			err = charles.AcceptInvitation("alice", inviteCharles, "0987.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("sharing the 1234 to Eve")
			inviteEve, err := bob.CreateInvitation("1234.txt", "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("sharing the 0987 to Grace")
			inviteGrace, err := charles.CreateInvitation("0987.txt", "grace")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve accepts right invitation")
			err = eve.AcceptInvitation("bob", inviteEve, "5678.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Grace accepts right invitation")
			err = grace.AcceptInvitation("charles", inviteGrace, "6543.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Sharing to frank from Eve")
			inviteFrank, err := eve.CreateInvitation("5678.txt", "frank")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Frank accepts right invitation")
			err = frank.AcceptInvitation("eve", inviteFrank, "1092.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Frank is able to append")
			err = frank.AppendToFile("1092.txt", []byte("Hello"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes bob :(")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob tries to append but fails")
			err = charles.AppendToFile("1234.txt", []byte("Hello"))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Eve tries to append but fails")
			err = charles.AppendToFile("5678.txt", []byte("Hello"))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles appends")
			err = charles.AppendToFile("0987.txt", []byte("Hello"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appends")
			err = alice.AppendToFile(aliceFile, []byte("Well Hello Back"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + "Hello" + "Hello" + "Well Hello Back")))

			userlib.DebugMsg("sharing the bobfile to doris, should error")
			_, err = bob.CreateInvitation("1234.txt", "doris")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Loading file...")
			_, err = bob.LoadFile("1234.txt")
			Expect(err).ToNot(BeNil())

			//test to make sure diff child nodes can still append to same file

		})
	})
})
