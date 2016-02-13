package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/atotto/clipboard"
	"github.com/mewbak/gopass"
)

var (
	StoreFile           = flag.String("file", defaultStoreFile, "Password Store File")
	del                 = flag.String("delete", "", "delete Entry")
	update              = flag.String("update", "", "update Entry")
	add                 = flag.String("add", "", "add Password Entry")
	home         string = os.Getenv("HOME")
	storeDir     string = home + "/.gpws"
	helpdocument string = `
Examples:
List Entries:
gpws

Add Entry in MyPasswordStore:
gpws -file MyPasswordStore -add entry

Delete entry:
gpws -delete entry

Update entry:
gpws -update entry

Get password for entry into clipboard:
gpws entry
`
)

const (
	defaultStoreFile = "Store"
)

func init() {
	_, err := os.Stat(storeDir)
	if os.IsNotExist(err) {
		err = os.Mkdir(storeDir, 0700)
		if err != nil {
			fmt.Println("Error create storedir:", err)
		}
	}
}

type record struct {
	Name, User string
	Pass       []byte
}

func Newrecord(name, user string, pass []byte) record {
	return record{
		Name: name,
		User: user,
		Pass: pass,
	}
}

func RecordInput(masterKey []byte, name string) (record record, err error) {
	user, err := UserInput("User: ")
	if err != nil {
		return record, err
	}

	plainpass, err := gopass.GetPass("Password: ")
	if err != nil {
		return record, fmt.Errorf("Error in GetPass: %s", err)
	}

	ciphertext, err := encrypt(masterKey, plainpass)
	if err != nil {
		return record, fmt.Errorf("Error in encrypt Password: %s", err)
	}
	record = Newrecord(name, user, []byte(ciphertext))
	return record, nil
}

func UserInput(prompt string) (text string, err error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	text, err = reader.ReadString('\n')
	if err != nil {
		return text, err
	}
	return text[:len(text)-1], nil
}

func PaddingKey(masterPass string) (padkey []byte, err error) {
	var b bytes.Buffer
	b.WriteString(masterPass)

	if len(b.String()) > 32 {
		return padkey, fmt.Errorf("Password can be max 32 bytes but is %d bytes", len(b.String()))
	}
	// append a until 32 bytes
	for i := len(b.String()); i < 32; i++ {
		b.WriteString("a")
	}
	return b.Bytes(), err
}

func MasterKeys() (masterKey []byte, masterPass string, err error) {
	masterPass, err = gopass.GetPass("Gimme MasterPassword: ")
	if err != nil {
		return masterKey, masterPass, fmt.Errorf("Error in Password input:", err)
	}
	masterKey, err = PaddingKey(masterPass)
	if err != nil {
		return masterKey, masterPass, fmt.Errorf("Error in Password input:", err)
	}
	return masterKey, masterPass, nil
}

func CheckMasterPass(masterKey []byte, masterPass string, cipherpass string) bool {
	plainpass, err := decrypt(masterKey, cipherpass)
	if err != nil {
		fmt.Println("Error decrypting Password in self")
		return false
	}

	if plainpass == masterPass {
		return true
	}
	fmt.Println("Wrong MasterPassword")
	return false
}

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Print(helpdocument)
	}

	flag.Parse()
	//validate flags
	if (*add != "" && *del != "") || (*add != "" && *update != "") || (*update != "" && *del != "") {
		fmt.Println("Error: -add, -delete and -update are exclusive parameters\n")
		flag.Usage()
		os.Exit(1)
	}
	if (*add != "" || *del != "" || *update != "") && len(flag.Args()) > 0 {
		flag.Usage()
		os.Exit(1)
	}

	s := NewPasswordStore(storeDir + "/" + *StoreFile)
	defer s.Save(storeDir + "/" + *StoreFile)

	// check password
	selfentry, err := s.Get("self")
	if err != nil {
		fmt.Println("Error getting self", err)
		os.Exit(1)
	}
	masterKey, masterPass, err := MasterKeys()
	if err != nil {
		fmt.Println("Error getting MasterKeys:", err)
		os.Exit(1)
	}
	if CheckMasterPass(masterKey, masterPass, string(selfentry.Pass)) {
		fmt.Println("Password OK")
	} else {
		os.Exit(1)
	}

	// add
	if *add != "" {
		if s.Exists(*add) {
			fmt.Printf("Entry %s already exists!\n", *add)
			os.Exit(0)
		}
		newrecord, err := RecordInput(masterKey, *add)
		if err != nil {
			fmt.Println(err)
		}
		if err = s.Set(newrecord.Name, newrecord); err != nil {
			fmt.Println("Error adding Entry:", err)
		}
	}

	//del
	if *del != "" {
		if *del == "self" {
			fmt.Printf("Entry self is Master Key for Password Store\nAbort now\n")
			os.Exit(1)
		}
		err = s.Delete(*del)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	//update
	if *update != "" {
		if err = s.Delete(*update); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		newrecord, err := RecordInput(masterKey, *update)
		if err != nil {
			fmt.Println(err)
		}
		if err = s.Set(newrecord.Name, newrecord); err != nil {
			fmt.Println("Error adding Entry:", err)
		}
	}

	//get
	if len(flag.Args()) == 1 {
		record, err := s.Get(flag.Arg(0))
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}

		plainpass, err := decrypt(masterKey, string(record.Pass))
		fmt.Printf("Username for %s is %s\n copy password into clipboard\n", flag.Arg(0), record.User)
		if err = clipboard.WriteAll(plainpass); err != nil {
			fmt.Println("Error: copy password into clipboard", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// list
	s.Print()
}
