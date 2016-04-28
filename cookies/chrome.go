package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"os/user"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	// Add sqlite3 support
	_ "github.com/mattn/go-sqlite3"
	"github.com/tmc/keyring"
)

var (
	defaultCookieFile = "%s/Library/Application Support/Google/Chrome/Default/Cookies"

	query  = "select name, value, encrypted_value from cookies where host_key like ?"
	salt   = []byte("saltysalt")
	iters  = 1003
	iv     = []byte("                ")
	length = 16
)

type chromeCookieRow struct {
	Name           string
	Value          string
	EncryptedValue string
}

// Chrome returns cookies associated with the particular URL as stored in the
// chrome cookies database.
func Chrome(rawURL, cookieFile string) (cookies []http.Cookie, err error) {

	pass, err := keyring.Get("Chrome Safe Storage", "Chrome")
	if err != nil {
		return cookies, err
	}
	key := pbkdf2.Key([]byte(pass), salt, iters, length, sha1.New)

	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	db, err := getCookieDB(cookieFile)
	if err != nil {
		return
	}
	defer db.Close()

	for _, hostKey := range getHostKeys(u.Host) {
		fmt.Println(hostKey)
		rows, err := db.Query(query, hostKey)
		if err != nil {
			return cookies, err
		}
		for rows.Next() {
			var name, value, encryptedValue sql.NullString

			err = rows.Scan(&name, &value, &encryptedValue)
			if err != nil {
				return cookies, err
			}

			c := http.Cookie{}
			if (value.Valid && value.String != "") || (encryptedValue.Valid && !strings.HasPrefix(encryptedValue.String, "v10")) {
				c.Name = name.String
				c.Value = value.String
			} else {
				decrypted, err := decryptCookieValue(key, []byte(encryptedValue.String))
				if err != nil {
					fmt.Println("unable to decrypt cookie value")
					return cookies, err
				}
				c.Name = name.String
				c.Value = string(decrypted)
			}

			cookies = append(cookies, c)
		}
	}

	return cookies, err
}

func decryptCookieValue(key, encryptedValue []byte) (decryptedValue []byte, err error) {
	// Encrypted value is prefixed with "v10", strip it off.
	encryptedValue = encryptedValue[3:]

	block, err := aes.NewCipher(key)
	aesDecrypter := cipher.NewCBCDecrypter(block, iv)

	aesDecrypter.CryptBlocks(decryptedValue, encryptedValue)

	return encryptedValue, err
}

func getCookieDB(cookieFile string) (*sql.DB, error) {
	if cookieFile == "" {
		usr, err := user.Current()
		if err != nil {
			return nil, err
		}
		cookieFile = fmt.Sprintf(defaultCookieFile, usr.HomeDir)
	}

	db, err := sql.Open("sqlite3", cookieFile)
	if err != nil {
		return nil, err
	}
	return db, err
}

func getHostKeys(hostname string) (hostKeys []string) {
	parts := strings.Split(hostname, ".")

	parts, domain := parts[0:len(parts)-2], parts[len(parts)-2:]

	for i := len(parts); i >= 0; i-- {
		hostKey := fmt.Sprintf("%s.%s",
			strings.Join(parts, "."),
			strings.Join(domain, "."),
		)

		hostKeys = append(hostKeys, hostKey, "."+hostKey)
	}

	return
}
