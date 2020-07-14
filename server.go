package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/pborman/getopt/v2"
	"github.com/ztrue/tracerr"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/yaml.v2"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"time"
)

type Config struct {
	Port uint16 `yaml:"port"`
	CookieName string `yaml:"cookie-name"`
	ClientID string `yaml:"client-id"`
	ClientSecret string `yaml:"client-secret"`
	RootPath string `yaml:"root-path"`
	CookiePath string `yaml:"cookie-path"`
	GitLabURL string `yaml:"gitlab-url"`
	CallbackURL string `yaml:"callback-url"`
	SecureCookie bool `yaml:"secure-cookie"`
	AccessControl []struct {
		Pattern string `yaml:"pattern"`
		Groups []string `yaml:"groups"`
		Compiled *regexp.Regexp
	} `yaml:"access-control"`
	Log string `yaml:"log"`
}

type GitlabToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn int `json:"expires_in"`
}

/*
type GitlabUser struct {
	Id string `json:"id"`
	Username string `json:"username"`
}
*/

type GitlabGroup struct {
	Name string `json:"name"`
}

type AuthInfo struct {
	Token string `json:"token"`
	Expiry int64 `json:"expiry"`
}

type SimpleError struct {
	Err string
}

func (e SimpleError) Error() string {
	return e.Err
}

var cfg Config
// var key []byte = make([]byte, 32)
var key [32]byte
var xLog *log.Logger

type LogWriter struct {
}

var logWriter = LogWriter{}

func (w * LogWriter) Write(p []byte) (n int, err error) {
	xLog.Printf("%s", string(p))
	return len(p), nil
}

func processConfigError(cfgFile string, err error) {
	if err != nil {
		xLog.Printf("Can not read %s: %s", cfgFile, err.Error())
		os.Exit(1)
	}
}

func doErr(err error) {
	if err != nil {
		tracerr.PrintSourceColor(err)
	}
}

func main() {

	defaultConfig := "gitlab-nginx-auth.yml"

	cfgFilePath := getopt.String('c', "", "Configuration file")
	helpFlag := getopt.Bool('h', "Print usage")

	getopt.Parse()

	if *helpFlag {
		getopt.Usage()
		os.Exit(1)
	}

	if "" == *cfgFilePath {
		cfgFilePath = &defaultConfig
	}

	// fmt.Printf("cfgFilePath: %s\n", *cfgFilePath)

	cfg = loadConfig(*cfgFilePath)
	if cfg.CookieName == "" { cfg.CookieName = "_this_auth" }
	if cfg.CookiePath == "" { cfg.CookiePath = "/" }

	regexpErrors := false
	for i := range cfg.AccessControl[:] {
		var err error
		acl := &cfg.AccessControl[i]
		acl.Compiled, err = regexp.Compile(acl.Pattern)
		if err != nil {
			fmt.Printf("Can not compile regular rexpression %s: %s", acl.Pattern, err.Error())
			regexpErrors = true
			/*
		} else {
			fmt.Printf("Compiled %s -> %s\n", acl.Pattern, acl.Compiled.String())
			 */
		}
	}

	if regexpErrors {
		processConfigError(*cfgFilePath, SimpleError{Err: "Regular expression errors"})
	}

	if len(cfg.AccessControl) == 0 {
		processConfigError(*cfgFilePath, SimpleError{Err: "No access control defined"})
	}

	_, err := rand.Read(key[:])
	if err != nil {
		fmt.Printf("Error generating secret key: %s\n", err.Error())
		os.Exit(1)
	}

	gin.SetMode(gin.ReleaseMode)

	if cfg.Log == "" {
		xLog = log.New(os.Stdout, "", 0)
	} else {
		gin.DisableConsoleColor()
		f, err := os.OpenFile(cfg.Log, os.O_WRONLY|os.O_CREATE|os.O_APPEND, os.FileMode(0755))
		processConfigError(*cfgFilePath, err)
		xLog = log.New(f, "", 0)
		//noinspection GoUnhandledErrorResult
		defer f.Close()
	}

	gin.DefaultWriter = &logWriter

	r := gin.Default()
	// r := gin.New()
	// r.Use(gin.Recovery())

	r.Use()

	root := r.Group(cfg.RootPath)
	root.GET("/check", func(c *gin.Context){

		var err error

		for {

			uri := c.GetHeader("x-original-uri")
			if uri == "" {
				c.AbortWithError(400, SimpleError{Err: "No original URL header in request"})
				return
			}

			var jweCookie string
			jweCookie, err = c.Cookie(cfg.CookieName)
			if err != nil { break }
			var jwe *jose.JSONWebEncryption
			jwe, err = jose.ParseEncrypted(jweCookie)
			if err != nil { break }
			var jsonData []byte
			jsonData, err = jwe.Decrypt(key[:])
			if err != nil { break }
			authData := AuthInfo{}
			err = json.Unmarshal(jsonData, &authData)
			if err != nil { break }

			if authData.Expiry < time.Now().Unix() { break }

			var groups []GitlabGroup
			groups, err = getGroups(authData.Token)
			if err != nil { break }

			haveGroups := map[string]bool{}
			for _, ch := range groups {
				haveGroups[ch.Name] = true
			}

			patternMatched := false

			for _, acl := range cfg.AccessControl {
				if acl.Compiled.MatchString(uri) {
					patternMatched = true
					for _, group := range acl.Groups {
						if _, ok := haveGroups[group]; ok {
							xLog.Printf("Request allowed, uri %s matched pattern %s, user has group %s\n", uri, acl.Pattern, group)
							c.Status(204)
							return
						}
					}
				}
			}

			var err403 string
			if patternMatched {
				err403 = fmt.Sprintf("User had no groups required for %s", uri)
			} else {
				err403 = fmt.Sprintf("No patterns match uri %s", uri)
			}

			c.AbortWithError(403, SimpleError{Err: err403})

			return

		}

		doErr(err)

		c.Status(401)
	})
	root.GET("/finish_login", func(c *gin.Context){
		// we set parameter "from" to contain the URL that we shall send the user to.
		// we get parameter "token" from Gitlab, which contains the authentication juice
		// try to get the user info then

		var err error

		for {

			code, exists := c.GetQuery("code")
			if !exists {
				err = SimpleError{Err: "no code query parameter"}
				break
			}

			var token *GitlabToken
			token, err = getAccessToken(code)
			if err != nil { break }

			// check if the access token even works before
			// signalling success.
			_, err = getGroups(token.AccessToken)
			if err != nil {
				break
			}

			authInfo := AuthInfo {
				Token:  token.AccessToken,
				Expiry: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).Unix(),
			}

			var jsonObj []byte
			jsonObj, err = json.Marshal(authInfo)
			if err != nil { break }

			var enc jose.Encrypter
			enc, err = jose.NewEncrypter(jose.A128CBC_HS256, jose.Recipient{Algorithm: jose.A256GCMKW, Key: key[:]}, nil)
			if err != nil { break }

			var jwe *jose.JSONWebEncryption
			jwe, err = enc.Encrypt(jsonObj)
			if err != nil { break }

			var jweStr string
			jweStr, err = jwe.CompactSerialize()
			if err != nil { break }

			c.SetCookie(cfg.CookieName, jweStr, token.ExpiresIn, cfg.CookiePath, "", cfg.SecureCookie, true)

			to, exists := c.GetQuery("state")
			var rdrTo string
			if exists {
				rdrTo = to
			} else {
				rdrTo = cfg.CallbackURL
			}

			c.Redirect(302, rdrTo)
			return

		}

		doErr(err)

		c.Status(500)

	})
	root.GET("/init_login", func(c *gin.Context) {

		for {

			// myUrl, err := makeMyURL("/finish_login", map[string]string {"from": c.Query("from")})
			myUrl, err := makeMyURL("/finish_login", nil)
			if err != nil { break }

			rUrl, err := makeGitlabURL("/oauth/authorize", map[string] string {
				"client_id" : cfg.ClientID,
				"redirect_uri" : *myUrl,
				"scope" : "read_api",
				"state" : c.Query("from"),
				"response_type" : "code",
			})

			if err != nil { break }

			c.Redirect(302, *rUrl)
			return

		}

		c.Status(500)

	})
	err = r.Run(fmt.Sprintf("127.0.0.1:%d", cfg.Port))
	if err != nil {
		xLog.Printf("%s", err.Error())
	}

}

func getAccessToken(code string) (*GitlabToken, error) {

	targetUrl, err := makeGitlabURL("/oauth/token", nil)
	if err != nil {
		return nil, err
	}

	myUrl, err := makeMyURL("/finish_login", nil)
	if err != nil {
		return nil, err
	}

	res, err := http.PostForm(*targetUrl, url.Values{
		"client_id": {cfg.ClientID},
		"client_secret":{cfg.ClientSecret},
		"code":{code},
		"grant_type": {"authorization_code"},
		"redirect_uri": {*myUrl},
	})

	if err != nil { return nil, err }

	//noinspection GoUnhandledErrorResult
	defer res.Body.Close()

	/*
	input, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
		fmt.Printf("token post: %s: %s\n", res.Status, string(input))
	 */

	if res.StatusCode != 200 {
		return nil, SimpleError{Err: fmt.Sprintf("Requesting token at %s: %d", *targetUrl, res.StatusCode)}
	}

	var gitlabToken GitlabToken
	d := json.NewDecoder(res.Body)
	err = d.Decode(&gitlabToken)
	// err = json.Unmarshal(input, &gitlabToken)
	if err != nil { return nil, err }
	return &gitlabToken, err

}

func getGroups(token string) ([]GitlabGroup, error) {

	var groups []GitlabGroup
	err := getGitLabObject(token, "/api/v4/groups", &groups, map[string]string {"min_access_level":"10"})
	if err != nil { return nil, err }
	return groups, nil

}

func getGitLabObject(token string, path string, into interface{}, query map[string]string) error {

	dUrl, err := urlStringWithQuery(cfg.GitLabURL, path, query)
	if err != nil { return err }
	req, err := http.NewRequest("GET", *dUrl, nil)
	if err != nil { return err }
	client := http.DefaultClient
	// fmt.Printf("Authorizing with %s\n", token)
	req.Header.Add("Authorization", "BEARER " + token)

	res, err := client.Do(req)
	if err != nil { return err }

	//noinspection GoUnhandledErrorResult
	defer res.Body.Close()

	xLog.Printf("invoked %s, got %s\n", *dUrl, res.Status)

	if res.StatusCode != 200 {
		return SimpleError{fmt.Sprintf("Response for %s: %d", *dUrl, res.StatusCode)}
	}

	d := json.NewDecoder(res.Body)
	err = d.Decode(into)
	if err != nil { return err }
	return nil

}

/*
func getUserInfo(token string) (*GitlabUser, error) {
	var user GitlabUser
	err := getGitLabObject(token, "/api/v4/user", user, nil)
	if err != nil { return nil, err }
	return &user, nil
}
*/

func urlWithQuery(from string, wsPath string, query map[string]string) (*url.URL, error) {
	rUrl, err := url.Parse(from)
	if err != nil {
		xLog.Printf("Error constructing request with %s/%s:%s\n", from, wsPath, err.Error())
		return nil, err
	}
	rUrl.Path = path.Join(rUrl.Path, wsPath)
	values := url.Values{}
	if query != nil {
		for k,v := range query {
			values.Add(k, v)
		}
	}
	rUrl.RawQuery = values.Encode()
	return rUrl, nil
}

func urlStringWithQuery(from string, path string, query map[string]string) (*string, error) {
	rUrl, err := urlWithQuery(from, path, query)
	if err != nil { return nil, err }
	str := rUrl.String()
	return &str, nil
}

func makeMyURL(path string, query map[string]string) (*string, error) {
	return urlStringWithQuery(cfg.CallbackURL, cfg.RootPath + path, query)
}

func makeGitlabURL(path string, query map[string]string) (*string, error) {
	return urlStringWithQuery(cfg.GitLabURL, path, query)
}

func loadConfig(cfgPath string) Config {
	cfgFile, err := os.Open(cfgPath)
	processConfigError(cfgPath, err)
	//noinspection GoUnhandledErrorResult
	defer cfgFile.Close()
	var cfg Config
	decoder := yaml.NewDecoder(cfgFile)
	err = decoder.Decode(&cfg)
	processConfigError(cfgPath, err)
	return cfg
}
