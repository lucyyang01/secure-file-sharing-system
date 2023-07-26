package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

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
	Username     string            //username
	Password_key []byte            //key generated from pbkdf
	Priv_rsa     userlib.PKEDecKey // private key for signatures
	Priv_sig     userlib.DSSignKey //private key for rsa encryption

	//things we need - private key generated from pwd, rsa pair, user signature pair, hashed username

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// info for each file, created when the file is created
type FileInfo struct {
	Content_head userlib.UUID //where the first block is located
	Content_tail userlib.UUID // where the last block is located
	File_key     []byte       //how to decrypt the file
}

type FileContentBlock struct {
	UUIDafter     userlib.UUID // random uuid that we store to point
	BlockContents []byte       // the actual contents itself
}

// info for the shared tree, created when the owner of a file shares it
type Shared struct {
	FileInfoUUID userlib.UUID //where the first block is located
	FileInfoKey  []byte       //how to decrypt the file

}

type Invitation struct {
	SharedUUID userlib.UUID
	SharedKey  []byte
	Owner      bool     //bool to tell if the person is an owner or not
	Sharedlist []string //file sharing information list in datastore
}

// NOTE: The following methods have toy (insecure!) implementations.
// function to encrypt then mac whatever is passed into it
func EncThenMac(thingToEncrypt []byte, secretkey []byte, purposeEnc string, purposeMAC string, iv []byte) (macResult []byte, err error) {

	//begin encryting struct
	hkdf_enc, err := userlib.HashKDF(secretkey, []byte(purposeEnc))
	if err != nil {
		return nil, errors.New("HKDF on enc error")
	}
	ciphertext := userlib.SymEnc(hkdf_enc[:16], iv, thingToEncrypt)

	//begin MACing struct
	hkdf_mac, err := userlib.HashKDF(secretkey, []byte(purposeMAC))
	if err != nil {
		return nil, errors.New("HKDF on mac error")
	}

	mac_cipher, err := userlib.HMACEval(hkdf_mac[:16], ciphertext)
	if err != nil {
		return nil, err
	}

	return append(mac_cipher, ciphertext...), nil
}

func DemacThenDecrypt(thingToDecrypt []byte, secretkey []byte, purposeDec string, purposeDeMAC string) (decrypted []byte, err error) {
	//demac the thing to decrypt
	demac_key, err := userlib.HashKDF(secretkey, []byte(purposeDeMAC))
	if err != nil {
		return nil, err
	}
	Mac_new, err := userlib.HMACEval(demac_key[:16], thingToDecrypt[64:])
	if err != nil {
		return nil, err
	}

	MAC_bool := userlib.HMACEqual(Mac_new, thingToDecrypt[:64])
	if !MAC_bool {
		return nil, errors.New("MAC does not match")
	}
	Decrypt_key, err := userlib.HashKDF(secretkey, []byte(purposeDec))
	if err != nil {
		return nil, err
	}
	decrypted_user := userlib.SymDec(Decrypt_key[:16], thingToDecrypt[64:])
	if err != nil {
		return nil, err
	}
	return decrypted_user, err // decrypted_user WILL STILL B MARSHALLED!
}

func (userdata *User) RetrieveFileInfo(filename string) (info *FileInfo, shared *Shared, owner *Invitation, err error) {
	//retrieve the owned struct

	ownerUUID, err := uuid.FromBytes(append(userlib.Hash([]byte(userdata.Username))[:8], userlib.Hash([]byte(filename))[:8]...))

	if err != nil {
		return nil, nil, nil, err
	}
	ownerStruct, err_bool := userlib.DatastoreGet(ownerUUID)
	if err_bool != true {
		return nil, nil, nil, errors.New("owner struct doesn't exist in datastore")
	}
	//retrieve the shared struct

	DEMAC_Owner, err := DemacThenDecrypt(ownerStruct, userdata.Password_key, filename+"ENC", filename+"MAC")
	if err != nil {
		return nil, nil, nil, errors.New("demac owner is wrong")
	}

	var file_name Invitation
	marsh_err := json.Unmarshal(DEMAC_Owner, &file_name)
	if marsh_err != nil {
		return nil, nil, nil, errors.New("can't unmarshal owner struct")
	}
	//retrieve shared struct
	sharedStruct, err_bool := userlib.DatastoreGet(file_name.SharedUUID)
	if !err_bool {
		return nil, nil, nil, errors.New("shared struct doesn't exist in datastore")
	}
	//mac doesn't match here
	demac_shared, err := DemacThenDecrypt(sharedStruct, file_name.SharedKey, "ENC", "MAC")
	if err != nil {
		return nil, nil, nil, errors.New("demac shared is wrong")
	}
	var sharedSt Shared
	err = json.Unmarshal(demac_shared, &sharedSt)
	if err != nil {
		return nil, nil, nil, err
	}
	fileInfoStruct, err_bool := userlib.DatastoreGet(sharedSt.FileInfoUUID)
	if !err_bool {
		return nil, nil, nil, errors.New("file info doesn't exist in datastore")
	}
	//retrieve info struct
	decrypt_fileInfoStruct, err := DemacThenDecrypt(fileInfoStruct, sharedSt.FileInfoKey, "ENC", "MAC")
	if err != nil {
		return nil, nil, nil, errors.New("demac info is wrong")
	}
	var infoSt FileInfo
	err = json.Unmarshal(decrypt_fileInfoStruct, &infoSt)
	if err != nil {
		return nil, nil, nil, err
	}

	return &infoSt, &sharedSt, &file_name, nil
}

// hash the username, create the key in keystore, key in pwd, signature pair, encrypt the user struct and store a mac somewhere
func InitUser(username string, password string) (userdataptr *User, err error) {
	//check to see if the user already exists, if it does then say sowwy :(
	//var userdata *User
	if username == "" {
		return nil, errors.New("Username cannot be empty.")
	}

	_, err_bool := userlib.KeystoreGet(username + "rsa")
	if err_bool {
		return nil, errors.New("username already taken")
	}

	//get the pointer to user
	userbyte := []byte(username)
	userHash := userlib.Hash(userbyte)
	computed_uuid, err := uuid.FromBytes(userHash[:16])

	if err != nil {
		return nil, err
	}
	//generate keys
	salt := userlib.RandomBytes(5)
	userHash_pwd := userHash[:8]
	pwd_string := userlib.Hash(append(userHash_pwd, userlib.Hash([]byte(password))[:8]...))
	pwd_key := userlib.Argon2Key(pwd_string, salt, 16) //PBKDF generated secret key

	//rsa key pairs
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	//digital signature key pair
	var s_sign userlib.DSSignKey
	var p_verify userlib.DSVerifyKey
	s_sign, p_verify, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	//make user struct
	userdata := User{username, pwd_key, sk, s_sign}

	//marsh the userdata
	user_marsh, err := json.Marshal(userdata) //convert user struct into byte array
	if err != nil {
		return nil, err
	}

	//full_user = append(mac_user, cypher_user...)
	full_user, err := EncThenMac(user_marsh, pwd_key, "password", "MAC", userlib.RandomBytes(16))
	if err != nil {
		return nil, err
	}
	//put things in data and keystore
	userlib.DatastoreSet(computed_uuid, full_user)     //store user
	userlib.KeystoreSet((username + "rsa"), pk)        //store user's public rsa key
	userlib.KeystoreSet((username + "sign"), p_verify) //store user's public signing key
	//keystore takes strings, datastore takes uuids

	//store the salt
	saltUUID, err := uuid.FromBytes(append(userHash_pwd, []byte("saltsalt")...))

	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(saltUUID, salt) //can store the salt directly bc other things will detect tampering
	//flatten struct, encrypt it, concatenate encryption with the hmac computed on the encryption, then when we
	//authenticate we can separate the two, recompute hmac on encrpytion and make sure it matches with the
	//encryption we already store

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	//recompute user uuid
	userbyte := []byte(username)
	userHash := userlib.Hash(userbyte)
	computed_uuid, err := uuid.FromBytes(userHash[:16])

	if err != nil {
		return nil, err
	}
	_, err_bool := userlib.KeystoreGet(username + "rsa")
	if !err_bool {
		return nil, errors.New("User not in keystore, rsa")
	}

	//get the user
	user_place, err_bool := userlib.DatastoreGet(computed_uuid)
	if !err_bool {
		return nil, errors.New("User doesn not exist")
	}

	//get the salt
	userHash_copy := userHash[:8]
	salt_UUID, err := uuid.FromBytes(append(userHash_copy, []byte("saltsalt")...))

	if err != nil {
		return nil, err
	}
	salt, err_bool := userlib.DatastoreGet(salt_UUID) //datastoreget returns a bool
	if !err_bool {
		return nil, errors.New("couldn't find salt")
	}
	//recompute pbkdf
	pwd_string := userlib.Hash(append(userHash_copy, userlib.Hash([]byte(password))[:8]...))
	recomputed_pbkdf := userlib.Argon2Key(pwd_string, salt, 16)

	decrypted_user, err := DemacThenDecrypt(user_place, recomputed_pbkdf, "password", "MAC")
	if err != nil {
		return nil, err
	}
	var userdata User

	err = json.Unmarshal(decrypted_user, &userdata)
	if err != nil {
		return nil, err
	}
	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.UserUUID))[:16])
	//create file info struct
	existing_info, existing_shared, _, err2 := userdata.RetrieveFileInfo(filename)
	//if the file already exists, overwrite it
	if err2 == nil {
		//delete all old file blocks
		curr := existing_info.Content_head
		for curr != existing_info.Content_tail {
			//load file block and decrypt it
			curr_block, err_bool := userlib.DatastoreGet(curr)
			if !err_bool {
				return errors.New("current block not in datastore")
			}
			decrypt_block, err := DemacThenDecrypt(curr_block, existing_info.File_key, "ENC", "MAC")
			if err != nil {
				return err
			}
			//unmarshal decrypted block
			var unmarsh_block FileContentBlock
			err = json.Unmarshal(decrypt_block, &unmarsh_block)
			if err != nil {
				return err
			}
			new_curr := unmarsh_block.UUIDafter
			userlib.DatastoreDelete(curr)
			curr = new_curr
		}
		var newContent FileContentBlock
		existing_info.Content_head = uuid.New()
		existing_info.Content_tail = uuid.New()
		newContent.UUIDafter = existing_info.Content_tail
		newContent.BlockContents = content
		marsh_info, err1 := json.Marshal(existing_info)
		if err1 != nil {
			return err1
		}
		encmac_info, err1 := EncThenMac(marsh_info, existing_shared.FileInfoKey, "ENC", "MAC", userlib.RandomBytes(16))
		if err1 != nil {
			return err1
		}
		marsh_newblock, err1 := json.Marshal(newContent)
		if err1 != nil {
			return err1
		}
		encmac_block, err1 := EncThenMac(marsh_newblock, existing_info.File_key, "ENC", "MAC", userlib.RandomBytes(16))
		if err1 != nil {
			return err1
		}
		userlib.DatastoreSet(existing_shared.FileInfoUUID, encmac_info)
		userlib.DatastoreSet(existing_info.Content_head, encmac_block)
		return err1
	} else {
		var created FileInfo
		created.Content_head = uuid.New()
		created.File_key = userlib.RandomBytes(16)
		created.Content_tail = uuid.New()

		//TODO: create structure for own name for file
		var ownName Invitation
		ownName.SharedKey = userlib.RandomBytes(16)
		//create deterministic uuid hash(username) + hash(filename)
		ownName.SharedUUID = uuid.New()
		if err != nil {
			return err
		}
		ownName.Owner = true

		own_json, err := json.Marshal(ownName)
		if err != nil {
			return err
		}

		own_MAC, err := EncThenMac(own_json, userdata.Password_key, filename+"ENC", filename+"MAC", userlib.RandomBytes(16))
		if err != nil {
			return err
		}

		Hashfile := userlib.Hash([]byte(filename))
		Hashname := userlib.Hash([]byte(userdata.Username))
		Hashname_copy := Hashname[:8]
		UserBytes, err := uuid.FromBytes(append(Hashname_copy, Hashfile[:8]...))
		if err != nil {
			return err
		}

		userlib.DatastoreSet(UserBytes, own_MAC)

		//TODO: create structure for shared block
		var Sharedfile Shared
		Sharedfile.FileInfoKey = userlib.RandomBytes(16)
		Sharedfile.FileInfoUUID = uuid.New()

		marsh_file, err := json.Marshal(created)
		if err != nil {
			return err
		}
		enc_fileinfo, err := EncThenMac(marsh_file, Sharedfile.FileInfoKey, "ENC", "MAC", userlib.RandomBytes(16))
		if err != nil {
			return err
		}
		userlib.DatastoreSet(Sharedfile.FileInfoUUID, enc_fileinfo)
		Shared_json, err := json.Marshal(Sharedfile)
		if err != nil {
			return err
		}
		own_Shared, err := EncThenMac(Shared_json, ownName.SharedKey, "ENC", "MAC", userlib.RandomBytes(16))
		if err != nil {
			return err
		}
		userlib.DatastoreSet(ownName.SharedUUID, own_Shared)

		//create file content block struct
		var filestruct FileContentBlock
		filestruct.BlockContents = content
		filestruct.UUIDafter = created.Content_tail

		//marshall, encrypt, mac the content block struct
		blockBytes, err := json.Marshal(filestruct)
		if err != nil {
			return err
		}
		encmac_block, err := EncThenMac(blockBytes, created.File_key, "ENC", "MAC", userlib.RandomBytes(16))
		if err != nil {
			return err
		}
		userlib.DatastoreSet(created.Content_head, encmac_block)

		userlib.DatastoreSet(Sharedfile.FileInfoUUID, enc_fileinfo)
		return err
	}
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	decrypt_fileInfoStruct, decrypt_shared, _, err := userdata.RetrieveFileInfo(filename) //retrieve file info struct
	if err != nil {
		return err
	}

	//create a new file content block
	var newContent FileContentBlock
	newContent.BlockContents = content
	store_tail := decrypt_fileInfoStruct.Content_tail
	decrypt_fileInfoStruct.Content_tail = uuid.New()
	newContent.UUIDafter = decrypt_fileInfoStruct.Content_tail

	//marshall filecontentblock, enc then mac, then store in datastore
	marshalled_contents, err := json.Marshal(newContent)
	if err != nil {
		return err
	}
	Enc_fileContents, err := EncThenMac(marshalled_contents, decrypt_fileInfoStruct.File_key, "ENC", "MAC", userlib.RandomBytes(16))
	if err != nil {
		return err
	}
	userlib.DatastoreSet(store_tail, Enc_fileContents)

	//marshall, enc then mac, restore the file info
	marshalled_fileinfo, err := json.Marshal(decrypt_fileInfoStruct)
	if err != nil {
		return err
	}
	Enc_fileInfo, err := EncThenMac(marshalled_fileinfo, decrypt_shared.FileInfoKey, "ENC", "MAC", userlib.RandomBytes(16))
	if err != nil {
		return err
	}

	userlib.DatastoreSet(decrypt_shared.FileInfoUUID, Enc_fileInfo)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	decrypt_fileInfoStruct, _, _, err := userdata.RetrieveFileInfo(filename)
	if err != nil {
		return nil, err
	}
	//debug load file

	fileAfter := decrypt_fileInfoStruct.Content_head
	var data []byte
	var unmarshaled_block FileContentBlock

	for fileAfter != decrypt_fileInfoStruct.Content_tail {

		//get and decrypt the fileAfter content block
		contentUUID, err_bool := userlib.DatastoreGet(fileAfter)
		if !err_bool {
			return nil, errors.New("file content block not in Datastore")
		}
		decrypted_block, err := DemacThenDecrypt(contentUUID, decrypt_fileInfoStruct.File_key, "ENC", "MAC")
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(decrypted_block, &unmarshaled_block)
		if err != nil {
			return nil, err
		}
		fileAfter = unmarshaled_block.UUIDafter
		data = append(data, unmarshaled_block.BlockContents...)
	}

	return data, nil
}

// two cases, the owner shares the file and someone who is shared owns the file
// when an owner shares a file, create a deterministic
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	//search keystore for the recipient user
	_, err_bool := userlib.KeystoreGet(recipientUsername + "rsa")
	if !err_bool {
		return uuid.Nil, errors.New("recipient user doesn't exist")
	}

	//check that file exists in namespace
	_, decrypted_shared, decrypted_owner, err := userdata.RetrieveFileInfo(filename)
	if err != nil {
		return uuid.Nil, err
	}
	//retrieve file info ensures that user has access to file and that file exists in user's namespace
	if decrypted_owner.Owner {
		decrypted_owner.Sharedlist = append(decrypted_owner.Sharedlist, recipientUsername)
		new_Owner_file, err := json.Marshal(decrypted_owner)
		if err != nil {
			return uuid.Nil, err
		}
		own_MAC, err := EncThenMac(new_Owner_file, userdata.Password_key, filename+"ENC", filename+"MAC", userlib.RandomBytes(16))
		if err != nil {
			return uuid.Nil, err
		}
		Hashfile := userlib.Hash([]byte(filename))
		Hashname := userlib.Hash([]byte(userdata.Username))
		Hashname_copy := Hashname[:8]
		UserBytes, err := uuid.FromBytes(append(Hashname_copy, Hashfile[:8]...))
		if err != nil {
			return uuid.Nil, err
		}

		userlib.DatastoreSet(UserBytes, own_MAC)
	}

	//can regenerate during revoke
	hkdf_shared_key, err := userlib.HashKDF(userdata.Password_key, []byte(filename+recipientUsername))
	if err != nil {
		return uuid.Nil, err
	}
	//create the invite
	var newInv Invitation
	newInv.Owner = false

	//if the owner shares a file create new shared struct based on recipient username
	if decrypted_owner.Owner {
		//create a new shared struct
		newInv.SharedKey = hkdf_shared_key[:16]
		var newShareStruct Shared
		newShareStruct.FileInfoUUID = decrypted_shared.FileInfoUUID
		newShareStruct.FileInfoKey = decrypted_shared.FileInfoKey
		//compute uuid for shared struct
		newShareUUID, err := uuid.FromBytes(append(userlib.Hash([]byte(recipientUsername))[:8], userlib.Hash([]byte(filename))[:8]...))
		if err != nil {
			return uuid.Nil, err
		}
		//marshal shared struct
		marshalled_newshare, err := json.Marshal(newShareStruct)
		if err != nil {
			return uuid.Nil, err
		}

		//change this
		Encmac_newshare, err := EncThenMac(marshalled_newshare, newInv.SharedKey, "ENC", "MAC", userlib.RandomBytes(16))
		if err != nil {
			return uuid.Nil, err
		}
		//store encrypted and maced new share struct
		userlib.DatastoreSet(newShareUUID, Encmac_newshare)
		newInv.SharedUUID = newShareUUID
	} else {
		//if not an owner
		newInv.SharedUUID = decrypted_owner.SharedUUID
		newInv.SharedKey = decrypted_owner.SharedKey
	}
	//store the invitation and return the uuid
	marsh_inv, err := json.Marshal(newInv)
	if err != nil {
		return uuid.Nil, err
	}
	//encrypt with rec pub key, sign with sender's priv sign
	//encrypt invitation with recipient's public key
	recPK, keystore_bool := userlib.KeystoreGet(recipientUsername + "rsa")
	if !keystore_bool {
		return uuid.Nil, errors.New("recipient's public key not in keystore")
	}

	enc_inv, err := userlib.PKEEnc(recPK, marsh_inv)
	if err != nil {
		return uuid.Nil, err
	}
	//sign invitation with sender's signature key
	sign_inv, err := userlib.DSSign(userdata.Priv_sig, enc_inv)
	if err != nil {
		return uuid.Nil, err
	}
	invUUIDstr := append([]byte(recipientUsername), []byte("inv")...)
	invUUID, err := uuid.FromBytes(userlib.Hash(invUUIDstr)[:16])
	if err != nil {
		return uuid.Nil, err

	}
	userlib.DatastoreSet(invUUID, append(sign_inv, enc_inv...))

	//PREVENT REVOKED USER FROM DECRYPTING THE FILE INFO STRUCT FROM THEIR OUTDATED SHARED STRUCT
	//make shared struct outdated by giving file info struct new location and only communicating it to people with access
	//if a non owner shares a file, point recipient user to existing shared struct
	return invUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//decrypt invite, change invite uuid to be whatever they set the filename to be

	//get send users signature in keystore
	Senduser_sign, err_bool := userlib.KeystoreGet(senderUsername + "sign")
	if !err_bool {
		return errors.New("User not in keystore (accept invite)")
	}

	//get invitation from uuid
	invite, err_bool := userlib.DatastoreGet(invitationPtr)
	if !err_bool {
		return errors.New("invite not in datastore (accept invite)")
	}
	//verify signature
	err := userlib.DSVerify(Senduser_sign, invite[256:], invite[:256])
	if err != nil {
		return err
	}
	//decrypt the rest of the invitation
	Dec_Invite, err := userlib.PKEDec(userdata.Priv_rsa, invite[256:])
	if err != nil {
		return err
	}

	//create a new uuid based on what the user has stated in the filename
	new_byte_uuid := append(userlib.Hash([]byte(userdata.Username))[:8], userlib.Hash([]byte(filename))[:8]...)
	new_UUID, err := uuid.FromBytes(new_byte_uuid)
	if err != nil {
		return err
	}

	//if datastore has this uuid, the file already exists in their namespace
	_, err_bool1 := userlib.DatastoreGet(new_UUID)
	if err_bool1 {
		return errors.New("file already exists in namespace")
	}

	//encrypt the information (don't unmarshal it since we would just need to remarshal it for the decryption)
	final_enc, err := EncThenMac(Dec_Invite, userdata.Password_key, filename+"ENC", filename+"MAC", userlib.RandomBytes(16))
	if err != nil {
		return err
	}

	//set the new location and encrypted info in datastore
	userlib.DatastoreSet(new_UUID, final_enc)
	userlib.DatastoreDelete(invitationPtr)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//go through each user in the owner shared list and revoke whoever, then change the information in the other shared structs
	// and change the file location.
	decrypted_fileInfo, decrypted_shared, decrypted_owner, err := userdata.RetrieveFileInfo(filename)
	if !decrypted_owner.Owner {
		return errors.New("not the file owner")
	}
	if err != nil {
		return err
	}

	//make sure recipient was actually invited
	wasInvited := false
	for _, item := range decrypted_owner.Sharedlist {
		if item == recipientUsername {
			wasInvited = true
		}
	}
	if !wasInvited {
		return errors.New("recipient never invited to the file")
	}
	//unaccepted invitation uuid
	invUUIDstr := append([]byte(recipientUsername), []byte("inv")...)
	invUUID, err := uuid.FromBytes(userlib.Hash(invUUIDstr)[:16])
	if err != nil {
		return err
	}
	//delete unaccepted invitation
	//search datastore for unaccepted inv uuid, if we can't find it then compute accepted inv uuid
	userlib.DatastoreDelete(invUUID)
	userlib.DatastoreDelete(decrypted_shared.FileInfoUUID)

	//get the first block
	curr := decrypted_fileInfo.Content_head
	var unmarshaled_block FileContentBlock

	//new uuid for the first block and the new key to encrypt stuff
	new_after := uuid.New()
	new_curr := uuid.New()
	new_Key := userlib.RandomBytes(16)
	var new_tail userlib.UUID

	for curr != decrypted_fileInfo.Content_tail {

		//change the information in it to point it to a new location and save that pointer outside the for loop
		//encrypt the block with the new key, then move it to the new location of the pre
		//get and decrypt the fileAfter content block

		//decrypt the block
		contentUUID, err_bool := userlib.DatastoreGet(curr)
		if !err_bool {
			return errors.New("file content block not in Datastore")
		}
		decrypted_block, err := DemacThenDecrypt(contentUUID, decrypted_fileInfo.File_key, "ENC", "MAC")
		if err != nil {
			return err
		}
		err = json.Unmarshal(decrypted_block, &unmarshaled_block)
		if err != nil {
			return err
		}
		//remove curr from data store and set curr to be the file after
		if curr == decrypted_fileInfo.Content_head {
			decrypted_fileInfo.Content_head = new_curr
		}
		userlib.DatastoreDelete(curr)
		curr = unmarshaled_block.UUIDafter

		//set information in the decrypted block to reflect the new uuid
		unmarshaled_block.UUIDafter = new_after

		data, err := json.Marshal(unmarshaled_block)
		if err != nil {
			return err
		}
		//encrypt it and put it back into datastore
		data, err = EncThenMac(data, new_Key, "ENC", "MAC", userlib.RandomBytes(16))
		if err != nil {
			return err
		}
		userlib.DatastoreSet(new_curr, data)

		if curr == decrypted_fileInfo.Content_tail {
			new_tail = new_after
		}
		//change the new location to be what after was set to
		new_curr = new_after
		new_after = uuid.New()

	}
	decrypted_fileInfo.Content_tail = new_tail
	decrypted_fileInfo.File_key = new_Key

	//change the location of the info struct as well
	Info_UUID := uuid.New()
	//change all the information in each shared struct to reflect the changes in the
	Info_Key := userlib.RandomBytes(16)

	for i, item := range decrypted_owner.Sharedlist {
		if item == recipientUsername {
			sharedList_copy1 := decrypted_owner.Sharedlist[:i]
			sharedList_copy2 := decrypted_owner.Sharedlist[i+1:]
			decrypted_owner.Sharedlist = append(sharedList_copy1, sharedList_copy2...)
		}
	}
	//encrypt the owner struct again to match the new mac
	new_owner, err := json.Marshal(decrypted_owner)
	if err != nil {
		return err
	}
	Owner_enc, err := EncThenMac(new_owner, userdata.Password_key, filename+"ENC", filename+"MAC", userlib.RandomBytes(16))
	if err != nil {
		return err
	}

	Hashfile := userlib.Hash([]byte(filename))
	Hashname := userlib.Hash([]byte(userdata.Username))
	UserBytes, err := uuid.FromBytes(append(Hashname[:8], Hashfile[:8]...))
	if err != nil {
		return err
	}
	userlib.DatastoreDelete(UserBytes)
	userlib.DatastoreSet(UserBytes, Owner_enc)

	//change info on the shared for the owner
	decrypted_shared.FileInfoKey = Info_Key
	decrypted_shared.FileInfoUUID = Info_UUID
	new_marsh_share, err := json.Marshal(decrypted_shared)
	if err != nil {
		return err
	}

	encrypt_shared, err := EncThenMac(new_marsh_share, decrypted_owner.SharedKey, "ENC", "MAC", userlib.RandomBytes(16))
	if err != nil {
		return err
	}
	userlib.DatastoreSet(decrypted_owner.SharedUUID, encrypt_shared)

	//item is each username
	var new_shared Shared
	for _, item := range decrypted_owner.Sharedlist {
		Struct_name := append(userlib.Hash([]byte(item))[:8], userlib.Hash([]byte(filename))[:8]...)
		Shared_struct_uuid, err := uuid.FromBytes(Struct_name)
		if err != nil {
			return err
		}
		new_shared.FileInfoKey = Info_Key
		new_shared.FileInfoUUID = Info_UUID
		hkdf_pass, err := userlib.HashKDF(userdata.Password_key, []byte(filename+item))
		if err != nil {
			return err
		}
		marshalled_shared, err := json.Marshal(new_shared)
		if err != nil {
			return err
		}
		new_shared_data, err := EncThenMac(marshalled_shared, hkdf_pass[:16], "ENC", "MAC", userlib.RandomBytes(16))
		if err != nil {
			return err
		}
		userlib.DatastoreSet(Shared_struct_uuid, new_shared_data)
	}
	Info_Marshal, err := json.Marshal(decrypted_fileInfo)
	if err != nil {
		return err
	}
	final_enc, err := EncThenMac(Info_Marshal, Info_Key, "ENC", "MAC", userlib.RandomBytes(16))
	if err != nil {
		return err
	}
	userlib.DatastoreSet(Info_UUID, final_enc)
	return nil
}
