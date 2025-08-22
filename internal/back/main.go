package back

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/argon2"
)

var users map[string]string = make(map[string]string)

type authReq struct {
  Login string `json:"login" validate:"required,min=1,max=20,login"`
  Password string `json:"password" validate:"required,min=6,max=20"`
}

var validate = validator.New()
var loginValidation = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

const (
  saltLength uint32 = 16

  argon2Time uint32 = 2
  argon2Memory uint32 = 64*1024
  argon2Threads uint8 = 4
  argon2KeyLen uint32 = 32

  hashSep string = "$"
  hashAlgorithm string = "argon2id"
  hashVersion string = "v=%d"
  hashParams string = "m=%d,t=%d,p=%d"
  hashSaltStr string = "%s"
  hashHashStr string = "%s"
)

var hashParts = []string{"", hashAlgorithm, hashVersion, hashParams, hashSaltStr, hashHashStr}

func generateSalt() ([]byte, error) {
  salt := make([]byte, saltLength)
  if _, err := rand.Read(salt); err != nil {
    return nil, fmt.Errorf("salt generation failed: %w", err)
  }
  return salt, nil
}

func hashPassword(password string) (string, error) {
  salt, err := generateSalt()
  if err != nil {
    return "", fmt.Errorf("password hashing failed: %w", err)
  }
  hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
  encodedHash := fmt.Sprintf(strings.Join(hashParts, hashSep),
                              argon2.Version,
                              argon2Memory,
                              argon2Time,
                              argon2Threads,
                              base64.RawStdEncoding.EncodeToString(salt),
                              base64.RawStdEncoding.EncodeToString(hash))
  return encodedHash, nil
}

func verifyPassword(password, encodedHash string) (bool, error) {
  parts := strings.Split(encodedHash, hashSep)
  if len(parts) != len(hashParts) {
    return false, errors.New("invalid hash format")
  }
  if parts[1] != hashParts[1] {
    return false, errors.New("unsupported hash algorithm")
  }
  var argon2Config struct {
    version int
    memory, time uint32
    threads uint8
  }
  fmt.Sscanf(parts[2], hashParts[2], &argon2Config.version)
  fmt.Sscanf(parts[3], hashParts[3], &argon2Config.memory, &argon2Config.time, &argon2Config.threads)
  salt, err := base64.RawStdEncoding.DecodeString(parts[4])
  if err != nil {
    return false, fmt.Errorf("salt decoding failed: %w", err)
  }
  hash, err := base64.RawStdEncoding.DecodeString(parts[5])
  if err != nil {
    return false, fmt.Errorf("hash decoding failed: %w", err)
  }
  compHash := argon2.IDKey([]byte(password), salt, argon2Config.time, argon2Config.memory, argon2Config.threads, uint32(len(hash)))
  return subtle.ConstantTimeCompare(hash, compHash) == 1, nil
}

func authenticateUser(login, password string) error {
  encodedHash, found := users[login]
  if !found {
    return errors.New("login not found")
  }
  isValid, err := verifyPassword(password, encodedHash)
  if err != nil {
    return fmt.Errorf("authentication failed: %w", err)
  }
  if !isValid {
    return errors.New("wrong password")
  }
  return nil
}

func registerUser(login, password string) error {
  _, found := users[login]
  if found {
    return errors.New("user already registered")
  }
  encodedHash, err := hashPassword(password)
  if err != nil {
    return fmt.Errorf("registration failed: %w", err)
  }
  users[login] = encodedHash
  return nil
}

func init() {
  validate.RegisterValidation("login", func(fl validator.FieldLevel) bool {
    return loginValidation.MatchString(fl.Field().String())
  })
}

func Start() int {
  http.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
    var req authReq
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
      http.Error(w, "Invalid JSON", http.StatusBadRequest)
      return
    }
    if err := validate.Struct(req); err != nil {
      http.Error(w, "Wrong JSON format", http.StatusBadRequest)
      return
    }
    if err := authenticateUser(req.Login, req.Password); err != nil {
      http.Error(w, "Login failed", http.StatusUnauthorized)
      return
    }
    _ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
  })
  http.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {

  })
  http.HandleFunc("POST /signup", func(w http.ResponseWriter, r *http.Request) {
    var req authReq
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
      http.Error(w, "Invalid JSON", http.StatusBadRequest)
      return
    }
    if err := validate.Struct(req); err != nil {
      http.Error(w, "Wrong JSON format", http.StatusBadRequest)
      return
    }    
    if err := registerUser(req.Login, req.Password); err != nil {
      http.Error(w, "Sign up failed", http.StatusBadRequest)
      return
    }
    _ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})    
  })
  if err := http.ListenAndServe(":3001", nil); err != nil {
    return 1
  }
  return 0
}
