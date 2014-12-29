package main

import (
	"encoding/gob"

	"errors"
	"fmt"
	"io"
	"os"

	"code.google.com/p/gopass"
)

type PasswordStore struct {
	entries map[string]record
}

func (s *PasswordStore) Get(key string) (record, error) {
	if s.Exists(key) {
		return s.entries[key], nil
	}
	return s.entries[key], errors.New("Entry not found")
}

func (s *PasswordStore) Exists(key string) bool {
	_, record := s.entries[key]
	if record {
		return true
	}
	return false
}

func (s *PasswordStore) Set(key string, entry record) error {
	if s.Exists(key) {
		return errors.New("Entry already exists")
	}
	s.entries[key] = entry
	return nil
}

func (s *PasswordStore) Delete(key string) error {
	if s.Exists(key) {
		delete(s.entries, key)
		return nil
	}
	return errors.New("Entry not found")
}

func (s *PasswordStore) Print() {
	i := 0
	for _, entry := range s.entries {
		fmt.Printf("[%d]: %s\n", i, entry.Name)
		i++
	}
}

func NewPasswordStore(filename string) *PasswordStore {
	s := &PasswordStore{
		entries: make(map[string]record),
	}
	if filename != "" {
		if err := s.load(filename); err != nil {
			fmt.Println("Error loading PasswordStore:", err)
			os.Exit(1)
		}
	}
	return s
}

func (s *PasswordStore) newMasterPass() error {

	pass1, err := gopass.GetPass("New Password for PasswordStore: ")
	if err != nil {
		return fmt.Errorf("Error in GetPass", err)
	}
	pass2, err := gopass.GetPass("Again: ")
	if err != nil {
		return fmt.Errorf("Error in GetPass", err)
	}

	if pass1 == pass2 {
		key, err := PaddingKey(pass1)
		if err != nil {
			return fmt.Errorf("Error in key creation", err)
		}
		cipher, err := encrypt(key, pass1)
		if err != nil {
			return fmt.Errorf("Error in encryption", err)
		}
		record1 := Newrecord("self", "", []byte(cipher))
		if err = s.Set(record1.Name, record1); err != nil {
			return fmt.Errorf("Error for self entry", err)
		}
	} else {
		return fmt.Errorf("Passwords doesn't match")
	}
	return nil
}

func (s *PasswordStore) load(filename string) error {
	f, err := os.Open(filename)
	if os.IsNotExist(err) {
		fmt.Printf("PasswordStore %s does not exists. Will create one\n", filename)
		if err = s.newMasterPass(); err != nil {
			return fmt.Errorf("Error creating new Store: %s", err)
		}
		if err = s.Save(filename); err != nil {
			return err
		}
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()

	d := gob.NewDecoder(f)
	for {
		var r record
		if err := d.Decode(&r); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if err = s.Set(r.Name, Newrecord(r.Name, r.User, r.Pass)); err != nil {
			return err
		}
	}
	return nil
}

func (s *PasswordStore) Save(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	d := gob.NewEncoder(f)
	for _, entry := range s.entries {
		if err := d.Encode(&entry); err != nil {
			return err
		}
	}
	return nil
}
