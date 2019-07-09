package main
//test
import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"
	"github.com/srinathgs/mysqlstore"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type City struct {

	ID          int    `json:"id,omitempty"  db:"ID"`
	Name        string `json:"name,omitempty"  db:"Name"`
	CountryCode string `json:"countryCode,omitempty"  db:"CountryCode"`
	District    string `json:"district,omitempty"  db:"District"`
	Population  int    `json:"population,omitempty"  db:"Population"`
}


type Country struct {
	//ここの(json:"~,omitempty")の~が項目の名前として帰ってくる
	//構造体の値の名前？的なのはデータを取り出すうえでは重要でない。
	Code           string          `json:"coda,omitempty"  db:"Code"`//基はcode,omitempty
	Name           string          `json:"name,omitempty"  db:"Name"`
	Continent      string          `json:"continent"  db:"Continent"`
	Region         string          `json:"region,omitempty"  db:"Region"`
	SurfaceArea    float64         `json:"surfacearea,omitempty"  db:"SurfaceArea"`
	IndepYear      sql.NullInt64   `json:"indepyear,omitempty"  db:"IndepYear"`
	Population     int             `json:"population,omitempty"  db:"Population"`
	LifeExpectancy sql.NullFloat64 `json:"lifeexpectancy,omitempty"  db:"LifeExpectancy"`//基はsql.NullFloat64
	GNP            sql.NullFloat64 `json:"gnp,omitempty"  db:"GNP"`
	GNPOld         sql.NullFloat64 `json:"gnpold,omitempty"  db:"GNPOld"`
	LocalName      string          `json:"localname,omitempty"  db:"LocalName"`
	GovernmentForm string          `json:"governmentform,omitempty"  db:"GovernmentForm"`
	HeadOfState    sql.NullString  `json:"headofstate,omitempty"  db:"HeadOfState"`
	Capital        sql.NullInt64   `json:"capital,omitempty"  db:"Capital"`
	Code2          string          `json:"code2,omitempty"  db:"Code2"`
}
type Countrylist struct{
	Code string `json:"code,omitempty"  db:"Code"`
	Name string `json:"name,omitempty"  db:"nameda"`//ここの（db:~はデータベースから取り出した時のカラム名ASがあるときはそちらで。
}


var (
	db *sqlx.DB
)

func main() {
	_db, err := sqlx.Connect("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", os.Getenv("MARIADB_USERNAME"), os.Getenv("MARIADB_PASSWORD"), os.Getenv("MARIADB_HOSTNAME"), "3306", os.Getenv("MARIADB_DATABASE")))
	if err != nil {
		log.Fatalf("Cannot Connect to Database: %s", err)
	}
	db = _db

	store, err := mysqlstore.NewMySQLStoreFromConnection(db.DB, "sessions", "/", 60*60*24*14, []byte("secret-token"))
	if err != nil {
		panic(err)
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(session.Middleware(store))

	e.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "pong")
	})
	e.POST("/login", postLoginHandler)
	e.POST("/logout",postLogoutHandler)
	e.POST("/signup", postSignUpHandler)

	//
	withLogin := e.Group("")
	withLogin.Use(checkLogin)
	withLogin.GET("/cities/:cityName", getCityInfoHandler)//一時的にwithLogin→e
	e.GET("/countries/:countryName", getCountryInfoHandler)//一時的にwithLogin→e
	e.GET("/country", getCountryListHandler)//一時的にwithLogin→e
	e.GET("/Tokyo", getTokyo)
	
	withLogin.GET("/whoami", getWhoAmIHandler)

	e.Start(":12602")
}

type Me struct {
	Username string `json:"username,omitempty"  db:"username"`
}



func getWhoAmIHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, Me{
		Username: c.Get("userName").(string),
	})
}

type LoginRequestBody struct {
	Username string `json:"username,omitempty" form:"username"`
	Password string `json:"password,omitempty" form:"password"`
}

type User struct {
	Username   string `json:"username,omitempty"  db:"Username"`
	HashedPass string `json:"-"  db:"HashedPass"`
}

func postSignUpHandler(c echo.Context) error {
	req := LoginRequestBody{}
	c.Bind(&req)

	// もう少し真面目にバリデーションするべき
	if req.Password == "" || req.Username == "" {
		// エラーは真面目に返すべき
		return c.String(http.StatusBadRequest, "項目が空です")
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("bcrypt generate error: %v", err))
	}

	// ユーザーの存在チェック
	var count int

	err = db.Get(&count, "SELECT COUNT(*) FROM users WHERE Username=?", req.Username)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
	}

	if count > 0 {
		return c.String(http.StatusConflict, "ユーザーが既に存在しています")
	}

	_, err = db.Exec("INSERT INTO users (Username, HashedPass) VALUES (?, ?)", req.Username, hashedPass)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
	}
	return c.NoContent(http.StatusCreated)
}

func postLoginHandler(c echo.Context) error {
	req := LoginRequestBody{}
	c.Bind(&req)

	user := User{}
	err := db.Get(&user, "SELECT * FROM users WHERE username=?", req.Username)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPass), []byte(req.Password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return c.NoContent(http.StatusForbidden)
		} else {
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	sess, err := session.Get("sessions", c)
	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusInternalServerError, "something wrong in getting session")
	}
	sess.Values["userName"] = req.Username
	sess.Save(c.Request(), c.Response())
	//fmt.Println("login sucsess!")//ここ追加
	return c.String(http.StatusOK, "login succeeded!")
	return c.NoContent(http.StatusOK)
}

func checkLogin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("sessions", c)
		if err != nil {
			fmt.Println(err)
			return c.String(http.StatusInternalServerError, "something wrong in getting session")
		}

		if sess.Values["userName"] == nil {
			return c.String(http.StatusForbidden, "please login")
		}
		c.Set("userName", sess.Values["userName"].(string))

		return next(c)
	}
}
//以下途中
func postLogoutHandler(c echo.Context) error {
	req := LoginRequestBody{}
	c.Bind(&req)

	sess, err := session.Get("sessions", c)
	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusInternalServerError, "something wrong in getting session")
	}
	sess.Values["userName"] = nil
	sess.Save(c.Request(), c.Response())
	return c.String(http.StatusOK, "logout succeeded!")
}

func getCityInfoHandler(c echo.Context) error {
	cityName := c.Param("cityName")

	city := City{}//上のtypeのCity
	db.Get(&city, "SELECT * FROM city WHERE city.Name=?", cityName)

	if city.Name == "" {	
		return c.NoContent(http.StatusNotFound)
	}
	return c.JSON(http.StatusOK, city)
}

func getCountryInfoHandler(c echo.Context) error {
	countryName := c.Param("countryName")

	country := Country{}//上のtypeのCountry
	err := db.Get(&country, "SELECT * FROM country WHERE country.Name=?", countryName)

	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusInternalServerError, "something wrong in getCountryInfoHandler")
	}
	return c.JSON(http.StatusOK, country)
}

func getCountryListHandler(c echo.Context) error {

	countrylist := []Countrylist{}
	err := db.Select(&countrylist, "SELECT Name As nameda,Code FROM country ")
	/*if countrylist.Name == "" {
		return c.NoContent(http.StatusNotFound)
	}*/
	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusInternalServerError, "something wrong in getCountryListHandler")
	}

	return c.JSON(http.StatusOK, countrylist)
}




func getTokyo(c echo.Context) error {

	city := City{}
	err := db.Get(&city, "SELECT * FROM city WHERE Name='Tokyo'")
	/*if city.Name == "" {
		return c.NoContent(http.StatusNotFound)
	}*/
	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusInternalServerError, "something wrong in getTokyo")
	}
	return c.JSON(http.StatusOK, city)
}


//これ以下自分で編集
//func getCountriesName()  {
//	countries := []Country{}
//	db.Select(&countries, "SELECT * FROM country ")
//
//
//	for _, conutry := range countries {
//		fmt.Printf("国名: %s\n", country.Name)
//	}
//}

func test(){
	fmt.Println("Connected!")
	cities := []City{}
	db.Select(&cities, "SELECT * FROM city WHERE CountryCode='JPN'")

	fmt.Println("日本の都市一覧")
	for _, city := range cities {
		fmt.Printf("都市名: %s, 人口: %d人\n", city.Name, city.Population)
	}
}
