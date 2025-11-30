package back

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/argon2"

	_ "github.com/joho/godotenv/autoload"
)

var dbConn *sql.DB
type authReq struct {
  Login string `json:"login" validate:"required,min=1,max=20,login"`
  Password string `json:"password" validate:"required,min=6,max=20"`
}
type logoutReq struct {
  Token string `json:"token" validate:"required,min=36,max=36,token"`
}
type changePasswordReq struct {
  Token string `json:"token" validate:"required,min=36,max=36,token"`
  Password string `json:"password" validate:"required,min=6,max=20"`
  NewPassword string `json:"new_password" validate:"required,min=6,max=20"`
}

var validate = validator.New()
var loginValidation = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
var tokenValidation = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$`)

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

var (
  dbHost string = os.Getenv("DB_HOST")
  dbPort string = os.Getenv("DB_PORT")
  dbName string = os.Getenv("DB_NAME")
  dbUser string = os.Getenv("DB_USER")
  dbPass string = os.Getenv("DB_PASS")
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

func authenticateUser(login, password string) (string, error) {
  data, err := getUserData(login)
  if err != nil {
    return "", fmt.Errorf("error getting user data: %w", err)
  }
  if data.login != login {
    return "", errors.New("login not found")
  }
  isValid, err := verifyPassword(password, data.encodedHash)
  if err != nil {
    return "", fmt.Errorf("authentication failed: %w", err)
  }
  if !isValid {
    return "", errors.New("wrong password")
  }
  token := addToken(login)
  return token, nil
}

func addToken(login string) string {
  token := uuid.New().String()
  _, err := dbConn.Exec(`INSERT INTO tokens
                        (token, login, expiration)
                        VALUES
                        ($1, $2, CURRENT_DATE + INTERVAL '1 day');`, token, login)
  if err != nil {
    return ""
  }
  return token
}

func registerUser(login, password string) (string, error) {
  data, err := getUserData(login)
  if err != nil {
    return "", fmt.Errorf("error checking user data: %w", err)
  }
  if data.login == login {
    return "", errors.New("user already registered")
  }
  encodedHash, err := hashPassword(password)
  if err != nil {
    return "", fmt.Errorf("registration failed: %w", err)
  }
  if err := setUserData(newUser(login, encodedHash)); err != nil {
    log.Println(err)
    return "", fmt.Errorf("error setting user data: %w", err)
  }
  token := addToken(login)
  return token, nil
}

func logoutUser(token string) error {
  _, err := dbConn.Exec(`DELETE FROM tokens WHERE token = $1`, token)
  if err != nil {
    return fmt.Errorf("failed to delete token data: %w", err)
  }
  
  return nil
}

func changePassword(token, password, newPassword string) error {
  var login string
  var err error
  login, err = getLogin(token)
  if err != nil {
    return err
  }
  if login == "" {
    return errors.New("login not found")
  }
  data, err := getUserData(login)
  if err != nil {
    return fmt.Errorf("error getting user data: %w", err)
  }
  if data.login != login {
    return errors.New("login not found")
  }
  isValid, err := verifyPassword(password, data.encodedHash)
  if err != nil {
    return fmt.Errorf("authentication failed: %w", err)
  }
  if !isValid {
    return errors.New("wrong password")
  }
  encodedHash, err := hashPassword(newPassword)
  if err != nil {
    return fmt.Errorf("registration failed: %w", err)
  }
  if err := updateUserData(newUser(login, encodedHash)); err != nil {
    log.Println(err)
    return fmt.Errorf("error setting user data: %w", err)
  }

  return nil
}

type UserData struct {
  login string
  encodedHash string
}

func newUser(login, encodedHash string) *UserData {
  return &UserData{login: login, encodedHash: encodedHash}
}

func getUserData(login string) (*UserData, error) {
  data := UserData{}
  err := dbConn.QueryRow(`SELECT login, encoded_hash FROM users WHERE login = $1 LIMIT 1;`, login).Scan(&data.login, &data.encodedHash)
  if err == sql.ErrNoRows {
    return &data, nil
  }
  if err != nil {
    return nil, fmt.Errorf("failed to get user data: %w", err)
  }
  return &data, nil
}

func setUserData(data *UserData) error {
  res, err := dbConn.Exec(`INSERT INTO users
                           (login, encoded_hash)
                           VALUES
                           ($1, $2);`, data.login, data.encodedHash)
  if err != nil {
    return err
  }
  n, err := res.RowsAffected()
  if err != nil {
    return err
  }
  if n == 0 {
    return errors.New("failed to set user data")
  }
  return nil
}

func updateUserData(data *UserData) error {
  res, err := dbConn.Exec(`UPDATE users
                           SET encoded_hash = $2
                           WHERE login = $1;`, data.login, data.encodedHash)
  if err != nil {
    return err
  }
  n, err := res.RowsAffected()
  if err != nil {
    return err
  }
  if n == 0 {
    return errors.New("failed to update user data")
  }
  return nil
}

func getLogin(token string) (string, error) {
  login := ""
  err := dbConn.QueryRow(`SELECT login FROM tokens WHERE token = $1 AND expiration > CURRENT_DATE LIMIT 1;`, token).Scan(&login)
  if err == sql.ErrNoRows {
    return login, nil
  }
  if err != nil {
    return "", fmt.Errorf("failed to get user login: %w", err)
  }
  return login, nil
}

func parseRequest(r *http.Request, req interface{}) error {
  if err := json.NewDecoder(r.Body).Decode(req); err != nil {
    return err
  }
  if err := validate.Struct(req); err != nil {
    return err
  }
  return nil
}

func init() {
  var err error
  connString := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=disable", dbHost, dbPort, dbName, dbUser, dbPass)
  dbConn, err = sql.Open("postgres", connString)
  if err != nil {
    log.Fatal("invalid db config", err)
  }
  if err = dbConn.Ping(); err != nil {
    log.Fatal("db unreachable", err)
  }
  validate.RegisterValidation("login", func(fl validator.FieldLevel) bool {
    return loginValidation.MatchString(fl.Field().String())
  })
  validate.RegisterValidation("token", func(fl validator.FieldLevel) bool {
    return tokenValidation.MatchString(fl.Field().String())
  })
}

func Start() int {
  defer dbConn.Close()

  http.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
    var req authReq
    var err error
    err = parseRequest(r, &req)
    if err != nil {
      http.Error(w, "Invalid JSON", http.StatusBadRequest)
      return
    }
    var token string
    token, err = authenticateUser(req.Login, req.Password)
    if err != nil {
      http.Error(w, "Login failed", http.StatusUnauthorized)
      return
    }
    _ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "token": token})
  })
  http.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
    var req logoutReq
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
      http.Error(w, "Invalid JSON", http.StatusBadRequest)
      return
    }
    if err := validate.Struct(req); err != nil {
      http.Error(w, "Invalid JSON", http.StatusBadRequest)
      return
    }
    if err := logoutUser(req.Token); err != nil {
      http.Error(w, "Logout failed", http.StatusInternalServerError)
      return
    }
    _ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
  })
  http.HandleFunc("POST /signup", func(w http.ResponseWriter, r *http.Request) {
    var req authReq
    var err error
    err = parseRequest(r, &req)
    if err != nil {
      http.Error(w, "Invalid JSON", http.StatusBadRequest)
      return
    }  
    var token string
    token, err = registerUser(req.Login, req.Password)  
    if err != nil {
      http.Error(w, "Sign up failed", http.StatusBadRequest)
      return
    }
    _ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "token": token})    
  })
  http.HandleFunc("POST /change_password", func(w http.ResponseWriter, r *http.Request) {
    var req changePasswordReq
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
      http.Error(w, "Invalid JSON", http.StatusBadRequest)
      return
    }
    if err := validate.Struct(req); err != nil {
      http.Error(w, "Invalid JSON", http.StatusBadRequest)
      return
    }
    if err := changePassword(req.Token, req.Password, req.NewPassword); err != nil {
      log.Println(err)
      http.Error(w, "Failed to change password", http.StatusInternalServerError)
      return
    }
    _ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
  })
  if err := http.ListenAndServe(":3001", nil); err != nil {
    return 1
  }
  return 0
}
