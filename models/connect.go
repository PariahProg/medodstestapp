/*	Файл реализующий подключение к бд.
	Изначально подключение происходит к служебной базе postgres, так как postgresql не разрешает подключаться к серверу без указания конкретной бд.
	После происходит проверка на наличие необходимой бд и, если она отсутствует, происходит создание с последующим заполнением с помощью миграций.
*/

package models

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

type dbconfig struct {
	Db struct {
		User     string
		Password string
		DbName   string
		Ssl      string
	} `json:"db"`
}

var Db *sql.DB

func isDbExists(dbName string) (bool, error) {
	var isExists bool
	err := Db.QueryRow("select exists(select * from pg_catalog.pg_database where datname = $1)", dbName).Scan(&isExists)
	return isExists, err
}

func createDb(dbName string) error {
	/*  К сожалению, для запроса create database невозможно создать запрос типа _, err := Db.Exec("create database $1", dbName).
	Это связано с тем, что create database должен быть полностью вычеслен в момент выполнения.
	Реализация ниже уязвима к sql инъекциям, однако, так как имя бд берется из конфигурационного файла, это безопасно.*/
	_, err := Db.Exec(fmt.Sprintf("create database %s;", dbName))
	return err
}

func applyMigrations(dbName string) error {
	driver, err := postgres.WithInstance(Db, &postgres.Config{})
	if err != nil {
		return err
	}

	migrations, err := migrate.NewWithDatabaseInstance("file://migrations", dbName, driver)
	if err != nil {
		return err
	}

	err = migrations.Up()
	if err != nil {
		return err
	}
	return nil
}

func OpenDb() error {
	file, err := os.Open("configs/config.json")
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	var config dbconfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return err
	}

	connStr := "user=" + string(config.Db.User) + " password=" + string(config.Db.Password) + " dbname=postgres" + " sslmode=" + string(config.Db.Ssl)
	Db, err = sql.Open("postgres", connStr)
	if err != nil {
		return err
	}

	isExists, err := isDbExists(config.Db.DbName)
	if err != nil {
		return err
	}

	if !isExists {
		err = createDb(config.Db.DbName)
		if err != nil {
			return err
		}
		connStr = "user=" + string(config.Db.User) + " password=" + string(config.Db.Password) + " dbname=" + string(config.Db.DbName) + " sslmode=" + string(config.Db.Ssl)
		Db, err = sql.Open("postgres", connStr)
		if err != nil {
			return err
		}

		err = applyMigrations(config.Db.DbName)
		if err != nil {
			return err
		}
	} else {
		connStr = "user=" + string(config.Db.User) + " password=" + string(config.Db.Password) + " dbname=" + string(config.Db.DbName) + " sslmode=" + string(config.Db.Ssl)
		Db, err = sql.Open("postgres", connStr)
		if err != nil {
			return err
		}
	}
	return nil
}
