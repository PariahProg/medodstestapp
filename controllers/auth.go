/* Данный файл содержит в себе контролеры, обрабатывающие запросы на сервер, а также некоторый вспомогательные функции.*/

package controllers

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"medodstestapp/models"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

type Config interface {
	configurate() error
}

type TokensConfig struct {
	AccessSign   string `json:"accessTokenSign"`
	RefreshSign  string `json:"refreshTokenSign"`
	AccessExpIn  int    `json:"accessTokenExpIn"`
	RefreshExpIn int    `json:"refreshTokenExpIn"`
	BcryptCost   int    `json:"bcryptCost"`
}

func (tc TokensConfig) configurate() error {
	file, err := os.Open("configs/config.json")
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &tConfig)
	if err != nil {
		return err
	}
	return nil
}

var tConfig TokensConfig

type MailerConfig struct {
	Mailer struct {
		User     string
		Password string
		Host     string
		Port     int
	} `json:"mailer"`
}

func (mc MailerConfig) configurate() error {
	file, err := os.Open("configs/config.json")
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &mConfig)
	if err != nil {
		return err
	}
	return nil
}

var mConfig MailerConfig

func cryptRefreshToken(token string) (string, error) { // шифрование refresh токена для хранения в бд
	/*  Так как refresh токен в моем случае также имеет тип JWT, а bcrypt может шифровать строки длиной до 72 байт, я предварительно шифрую его в sha256 для уменьшения длины.
	Технически, это занимает некоторое дополнительное время, но скорость работы sha256 на 3+ порядка быстрее bcrypt, поэтому разница в скорости будет несущественной*/
	sha256Hash := sha256.New()
	sha256Hash.Write([]byte(token))
	hash, err := bcrypt.GenerateFromPassword(sha256Hash.Sum(nil), tConfig.BcryptCost)
	return string(hash), err
}

func createTokens(guid string, ip string) (string, string, error) { //создание пары Access, Refresh
	if tConfig == (TokensConfig{}) {
		err := tConfig.configurate()
		if err != nil {
			return "", "", err
		}
	}
	type CustomClaims struct {
		Guid string `json:"guid"`
		Ip   string `json:"ip"`
		jwt.StandardClaims
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, CustomClaims{
		guid,
		ip,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Duration(tConfig.AccessExpIn) * time.Second).Unix(),
			Issuer:    "medodstestapp",
		},
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, CustomClaims{
		guid,
		ip,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Duration(tConfig.RefreshExpIn) * time.Second).Unix(),
			Issuer:    "medodstestapp",
		},
	})

	accessTokenSigned, err := accessToken.SignedString([]byte(tConfig.AccessSign))
	if err != nil {
		return "", "", err
	}

	refreshTokenSigned, err := refreshToken.SignedString([]byte(tConfig.RefreshSign))
	if err != nil {
		return "", "", err
	}

	hashToken, err := cryptRefreshToken(refreshTokenSigned) // Шифруем refresh
	if err != nil {
		return "", "", err
	}

	err = models.UpdateToken(guid, hashToken) // Записываем его в бд
	if err != nil {
		return "", "", err
	}

	return accessTokenSigned, refreshTokenSigned, nil
}

func sendWarningEmail(email string, ip string) error { // отправка warning email, если поменялся ip адрес
	if mConfig == (MailerConfig{}) {
		err := mConfig.configurate()
		if err != nil {
			return err
		}
	}
	m := gomail.NewMessage()
	m.SetHeader("From", mConfig.Mailer.User)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Новое подключение к вашей учетной записи")
	body := fmt.Sprintf("<h2>Мы заметили, что над вашим аккаунтом совершаются действия с нетипичного для вас ip: %s\nЕсли это были не вы, срочно поменяйте пароль!</h2>", ip)
	m.SetBody("text/html", body)
	d := gomail.NewDialer(mConfig.Mailer.Host, mConfig.Mailer.Port, mConfig.Mailer.User, mConfig.Mailer.Password)
	err := d.DialAndSend(m)
	return err
}

func GetTokens(w http.ResponseWriter, r *http.Request) { // контроллер для эндпоинта получения пары Access, Refresh
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	guid := r.URL.Query().Get("guid")
	if guid == "" {
		http.Error(w, "No guid provided!", http.StatusBadRequest)
		return
	}

	isGuid, _ := regexp.Compile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	if !isGuid.MatchString(guid) {
		http.Error(w, "Incorrect guid!", http.StatusBadRequest)
		return
	}

	ip := r.RemoteAddr

	accessToken, refreshToken, err := createTokens(guid, ip)
	if err != nil {
		http.Error(w, "JWT creation error!", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{ // Refresh храним в защищенной куке, чтобы к нему нельзя было получить доступ из кода клиента
		Name:     "refresh-token",
		Value:    refreshToken,
		Expires:  time.Now().Add(time.Duration(tConfig.RefreshExpIn) * time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	type Response struct {
		AccessToken string `json:"access-token"`
	}

	resp := Response{
		AccessToken: accessToken,
	}

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Internal error!", http.StatusInternalServerError)
		return
	} else {
		w.Header().Set("Content-Type", "application/json") // Access отдаем в теле ответа в формате JSON
		w.WriteHeader(http.StatusOK)
		w.Write(jsonResp)
	}
}

func RefreshTokens(w http.ResponseWriter, r *http.Request) { // контроллер для эндпоинта рефреша токенов
	/*  Так как данного уточнения не было в задании, я исхожу из того, что на страницу рефреша пользователь попадает уже после валидации Access токена.
	Таким образом, в контроллере валидируется только Refresh. Так как Refresh имеет формат JWT и подписан, это также безопасно.*/
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return
	}

	refreshTokenCookie, err := r.Cookie("refresh-token")
	if err != nil {
		http.Error(w, "Refresh token not provided!", http.StatusBadRequest)
		return
	}
	refreshToken := refreshTokenCookie.Value

	if tConfig == (TokensConfig{}) {
		err := tConfig.configurate()
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	rt, err := jwt.Parse(refreshToken, func(t *jwt.Token) (interface{}, error) {
		return []byte(tConfig.RefreshSign), nil
	})

	if rt.Valid {
		claims, ok := rt.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Internal server error!", http.StatusInternalServerError)
			return
		}

		/* Сравниваем токен с тем, который в базе, чтобы предотвратить повторное использование. */
		hashedToken, err := models.ReadUserToken(claims["guid"].(string))
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Correct refresh token is needed!")
			http.Error(w, "Refresh token is incorrect!", http.StatusUnauthorized)
			return
		}

		sha256Hash := sha256.New()
		sha256Hash.Write(([]byte(refreshToken)))
		err = bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(sha256Hash.Sum(nil)))
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Correct refresh token is needed!")
			http.Error(w, "Refresh token is incorrect!", http.StatusUnauthorized)
			return
		}

		currentIp := r.RemoteAddr
		if currentIp != claims["ip"].(string) { // если поменялся ip, посылаем email warning
			email, err := models.ReadUserEmail(claims["guid"].(string))
			if err != nil {
				http.Error(w, "Sending email error!", http.StatusInternalServerError)
				return
			}
			err = sendWarningEmail(email, currentIp)
			if err != nil {
				http.Error(w, "Sending email error!", http.StatusInternalServerError)
				return
			}
		}

		accessToken, refreshToken, err := createTokens(claims["guid"].(string), claims["ip"].(string))
		if err != nil {
			http.Error(w, "JWT creation error!", http.StatusInternalServerError)
			return
		} else {
			http.SetCookie(w, &http.Cookie{
				Name:     "refresh-token",
				Value:    refreshToken,
				Expires:  time.Now().Add(time.Duration(tConfig.RefreshExpIn) * time.Second),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})

			type Response struct {
				AccessToken string `json:"access-token"`
			}

			resp := Response{
				AccessToken: accessToken,
			}

			jsonResp, err := json.Marshal(resp)
			if err != nil {
				http.Error(w, "Internal error!", http.StatusInternalServerError)
				return
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write(jsonResp)
			}
		}
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			http.Error(w, "Incorrect refresh token!", http.StatusBadRequest)
			return
		} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
			w.Header().Set("WWW-Authenticate", "Refresh token is expired!")
			http.Error(w, "Refresh token is expired!", http.StatusUnauthorized)
			return
		} else {
			http.Error(w, "Incorrect refresh token", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Incorrect refresh token", http.StatusBadRequest)
		return
	}
}
