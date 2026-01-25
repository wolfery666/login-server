package server

import (
	"context"
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
	"time"

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
type changePasswordReq struct {
  Password string `json:"password" validate:"required,min=6,max=20"`
  NewPassword string `json:"new_password" validate:"required,min=6,max=20"`
}

type Token struct {
  value string
  expires time.Time
}
type httpHandler func(http.ResponseWriter, *http.Request)

type ctxKey string

const loginKey ctxKey = "login"
const tokenKey ctxKey = "token"

var validate = validator.New()
var loginValidation = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
var tokenValidation = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var tokenValidationTag = "min=36,max=36,token"

var ErrorLog *log.Logger

var errLoginNotFound = errors.New("login not found")
var errUserDataNotFound = errors.New("user data not found")
var errWrongPassword = errors.New("wrong password")
var errUserAlreadyRegistered = errors.New("user already registered")

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
    return "", fmt.Errorf("hash password: %w", err)
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

func verifyPassword(password, encodedHash string) error {
  parts := strings.Split(encodedHash, hashSep)
  if len(parts) != len(hashParts) {
    return errors.New("invalid hash format")
  }
  if parts[1] != hashParts[1] {
    return errors.New("unsupported hash algorithm")
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
    return fmt.Errorf("salt decoding failed: %w", err)
  }
  hash, err := base64.RawStdEncoding.DecodeString(parts[5])
  if err != nil {
    return fmt.Errorf("hash decoding failed: %w", err)
  }
  compHash := argon2.IDKey([]byte(password), salt, argon2Config.time, argon2Config.memory, argon2Config.threads, uint32(len(hash)))
  if subtle.ConstantTimeCompare(hash, compHash) != 1 {
    return errWrongPassword
  }
  return nil
}

func verifyUser(login, password string) error {
  data, err := getUserData(login)
  if err != nil {
    return fmt.Errorf("failed to get user data: %w", err)
  }
  if data.login != login {
    return fmt.Errorf("login %s: %w", login, errUserDataNotFound)
  }
  if err := verifyPassword(password, data.encodedHash); err != nil {
    return fmt.Errorf("password verification failed: %w", err)
  }
  return nil
}

func createToken(login string) (*Token, error) {
  token := uuid.New().String()
  expiration := time.Now().Add(24*time.Hour)
  _, err := dbConn.Exec(`INSERT INTO tokens
                        (token, login, expiration)
                        VALUES
                        ($1, $2, $3);`, token, login, expiration)
  if err != nil {
    return nil, fmt.Errorf("db error, token insertion: %w", err)
  }
  return &Token{token, expiration}, nil
}

func registerUser(login, password string) error {
  data, err := getUserData(login)
  if err != nil {
    return fmt.Errorf("failed to get user data: %w", err)
  }
  if data.login == login {
    return fmt.Errorf("login %s: %w", login, errUserAlreadyRegistered)
  }
  encodedHash, err := hashPassword(password)
  if err != nil {
    return fmt.Errorf("password hashing failed: %w", err)
  }
  if err := setUserData(newUser(login, encodedHash)); err != nil {
    return fmt.Errorf("failed to set user data: %w", err)
  }
  return nil
}

func logoutUser(token string) error {
  _, err := dbConn.Exec(`DELETE FROM tokens WHERE token = $1`, token)
  if err != nil {
    return fmt.Errorf("db error, token deletion: %w", err)
  }
  
  return nil
}

func updateUser(login, password string) error {
  encodedHash, err := hashPassword(password)
  if err != nil {
    return fmt.Errorf("password hashing failed: %w", err)
  }
  if err := updateUserData(newUser(login, encodedHash)); err != nil {
    return fmt.Errorf("failed to update user data: %w", err)
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
    return nil, fmt.Errorf("db error, get user data: %w", err)
  }
  return &data, nil
}

func setUserData(data *UserData) error {
  res, err := dbConn.Exec(`INSERT INTO users
                           (login, encoded_hash)
                           VALUES
                           ($1, $2);`, data.login, data.encodedHash)
  if err != nil {
    return fmt.Errorf("db error, insert user data: %w", err)
  }
  n, err := res.RowsAffected()
  if err != nil {
    return err
  }
  if n == 0 {
    return errors.New("db error, user data not inserted")
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
    return fmt.Errorf("db error, update user data: %w", err)
  }
  if n == 0 {
    return errors.New("db error, user data not updated")
  }
  return nil
}

func getLogin(token string) (string, error) {
  var login string
  err := dbConn.QueryRow(`SELECT login FROM tokens WHERE token = $1 AND expiration > CURRENT_DATE LIMIT 1;`, token).Scan(&login)
  if err == sql.ErrNoRows {
    return "", fmt.Errorf("token %s: %w", token, errLoginNotFound)
  }
  if err != nil {
    return "", fmt.Errorf("db error, failed to get login: %w", err)
  }
  return login, nil
}

func parseRequest(r *http.Request, req any) error {
  if err := json.NewDecoder(r.Body).Decode(req); err != nil {
    return fmt.Errorf("json decoding failed: %w", err)
  }
  if err := validate.Struct(req); err != nil {
    return fmt.Errorf("json validation failed: %w", err)
  }
  return nil
}

func authHandler(handler httpHandler) httpHandler {
  return func(w http.ResponseWriter, r *http.Request) {
    logPrefix := "auth: "
    cookie, err := r.Cookie("token")
    if err != nil {
      ErrorLog.Println(logPrefix, "failed to get 'token' cookie: ", err)
      switch {
      case errors.Is(err, http.ErrNoCookie):
        http.Error(w, "", http.StatusUnauthorized)
      default:
        http.Error(w, "", http.StatusInternalServerError)
      }
      return
    }
    token := cookie.Value
    if err := validate.Var(token, tokenValidationTag); err != nil {
      ErrorLog.Println(logPrefix, "token validation error: ", err)
      http.Error(w, "", http.StatusUnauthorized)
      return
    }   
    if login, err := getLogin(token); err != nil {
      ErrorLog.Println(logPrefix, "failed to get login: ", err)
      switch {
      case errors.Is(err, errLoginNotFound):
        http.Error(w, "", http.StatusUnauthorized)
      default:
        http.Error(w, "", http.StatusInternalServerError)
      }
      return
    } else {
      ctx := r.Context()
      ctx = context.WithValue(ctx, loginKey, login)
      ctx = context.WithValue(ctx, tokenKey, token)
      r = r.WithContext(ctx)
    }
    handler(w, r)
 } 
}

func setTokenCookie(w http.ResponseWriter, token *Token) {
  cookie := http.Cookie{Name: "token", Value: token.value, Path: "/", Expires: token.expires, HttpOnly: true}
  http.SetCookie(w, &cookie)
}

func root(w http.ResponseWriter, r *http.Request) {}

func login(w http.ResponseWriter, r *http.Request) {
  var req authReq
  logPrefix := "login: "
  if err := parseRequest(r, &req); err != nil {
    ErrorLog.Println(logPrefix, "parse request error: ", err)
    http.Error(w, "", http.StatusBadRequest)
    return
  } 
  if err := verifyUser(req.Login, req.Password); err != nil {
    ErrorLog.Println(logPrefix, "user verification error: ", err)
    switch {
    case errors.Is(err, errUserDataNotFound) || errors.Is(err, errWrongPassword):
      http.Error(w, "", http.StatusUnauthorized)
    default:
      http.Error(w, "", http.StatusInternalServerError)
    }
    return
  }
  token, err := createToken(req.Login)
  if err != nil {
    ErrorLog.Println(logPrefix, "token creation error: ", err)
    http.Error(w, "", http.StatusInternalServerError)
    return    
  }
  setTokenCookie(w, token)
}

func signup(w http.ResponseWriter, r *http.Request) {
  var req authReq
  logPrefix := "sign up: "
  if err := parseRequest(r, &req); err != nil {
    ErrorLog.Println(logPrefix, "parse request error: ", err)
    http.Error(w, "", http.StatusBadRequest)
    return
  }   
  if err := registerUser(req.Login, req.Password); err != nil {
    ErrorLog.Println(logPrefix, "user registration error: ", err)
    switch {
    case errors.Is(err, errUserAlreadyRegistered):
      http.Error(w, "", http.StatusNotAcceptable)
    default:
      http.Error(w, "", http.StatusInternalServerError)
    }
    return
  }
  token, err := createToken(req.Login)
  if err != nil {
    ErrorLog.Println(logPrefix, "token creation error: ", err)
    http.Error(w, "", http.StatusInternalServerError)
    return
  }
  setTokenCookie(w, token)
}

func logout(w http.ResponseWriter, r *http.Request) {
  token := r.Context().Value(tokenKey).(string)
  logPrefix := "logout: "
  if err := logoutUser(token); err != nil {
    ErrorLog.Println(logPrefix, "user logout error: ", err)
    http.Error(w, "", http.StatusInternalServerError)
    return
  }
}

func changePassword(w http.ResponseWriter, r *http.Request) {
  var req changePasswordReq
  login := r.Context().Value(loginKey).(string)
  logPrefix := "change password: "
  if err := parseRequest(r, &req); err != nil {
    ErrorLog.Println(logPrefix, "parse request error: ", err)
    http.Error(w, "", http.StatusBadRequest)
    return
  }
  if err := verifyUser(login, req.Password); err != nil {
    ErrorLog.Println(logPrefix, "user verification error: ", err)
    switch {
    case errors.Is(err, errUserDataNotFound) || errors.Is(err, errWrongPassword):
      http.Error(w, "", http.StatusUnauthorized)
    default:
      http.Error(w, "", http.StatusInternalServerError)
    }
    return
  }
  if err := updateUser(login, req.NewPassword); err != nil {
    ErrorLog.Println(logPrefix, "user update error: ", err)
    http.Error(w, "", http.StatusInternalServerError)
    return
  }
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
  ErrorLog = log.New(os.Stdout, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func Start() int {
  defer dbConn.Close()

  mux := http.NewServeMux()

  mux.HandleFunc("OPTIONS /", root)
  mux.HandleFunc("GET /", authHandler(root))
  mux.HandleFunc("POST /login", login)
  mux.HandleFunc("POST /signup", signup)
  mux.HandleFunc("POST /logout", authHandler(logout))
  mux.HandleFunc("POST /change_password", authHandler(changePassword))

  if err := http.ListenAndServe(":3001", mux); err != nil {
    return 1
  }
  return 0
}
