/* Файл user.go - модель для взаимодействия с таблицей Users.
Таблица Users - единственная таблица в бд и имеет набор полей: id(bigserial), guid(uuid), token(string), email(string)
Так как в тестовом задании не стоит задачи регистрации и аутентификации пользователя, поля вроде login и password опущены. */

package models

import (
	_ "github.com/lib/pq"
)

func UpdateToken(guid string, token string) error { // обновить refresh token в таблице
	_, err := Db.Exec("update public.\"users\" set token = $1 where guid = $2", token, guid)
	if err != nil {
		return err
	}
	return nil
}

func ReadUserEmail(guid string) (string, error) { // получить email из таблицы для того, чтобы послать email warning
	row := Db.QueryRow("select email from public.\"users\" where guid = $1", guid)
	var email string
	err := row.Scan(&email)
	if err != nil {
		return "", err
	}
	return email, nil

}

func ReadUserToken(guid string) (string, error) { // получить refresh token
	row := Db.QueryRow("select token from public.\"users\" where guid = $1", guid)
	var token string
	err := row.Scan(&token)
	if err != nil {
		return "", err
	}
	return token, nil
}
