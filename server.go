package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/pborman/getopt/v2"
	"github.com/peterhellberg/link"
	"github.com/scylladb/go-set/strset"
	"github.com/ztrue/tracerr"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/yaml.v2"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"time"
)

type Config struct {
	Port          uint16 `yaml:"port"`
	CookieName    string `yaml:"cookie-name"`
	ClientID      string `yaml:"client-id"`
	ClientSecret  string `yaml:"client-secret"`
	RootPath      string `yaml:"root-path"`
	CookiePath    string `yaml:"cookie-path"`
	GitLabURL     string `yaml:"gitlab-url"`
	CallbackURL   string `yaml:"callback-url"`
	SecureCookie  bool   `yaml:"secure-cookie"`
	PageSize      uint   `yaml:"page-size"`
	AccessControl []struct {
		Pattern  string   `yaml:"pattern"`
		Groups   []string `yaml:"groups"`
		Compiled *regexp.Regexp
	} `yaml:"access-control"`
	SignUserInfo *struct {
		PrivateKeyFile string `yaml:"private-key"`
		SharedKey      string `yaml:"shared-key"`
		Algorithm      string `yaml:"algorithm"`
		HeaderName     string `yaml:"header-name"`
	} `yaml:"sign-user-info"`
	Log     string `yaml:"log"`
	Refused string `yaml:"refused-template"`
}

type GitlabToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   uint   `json:"expires_in"`
}

type GitlabUser struct {
	Id       uint   `json:"id"`
	UserName string `json:"username"`
	Name     string `json:"name"`
}

type SignedUserInfo struct {
	User   GitlabUser `json:"user"`
	Groups []string   `json:"groups"`
	Issued uint64     `json:"issued"`
}

type GitlabGroup struct {
	Name string `json:"name"`
}

type AuthInfo struct {
	Token  string `json:"token"`
	Expiry int64  `json:"expiry"`
}

type SimpleError struct {
	Err string
}

type LogWriter struct {
}

var cfg Config

// var key []byte = make([]byte, 32)
var key [32]byte
var xLog *log.Logger
var logWriter = LogWriter{}
var userInfoSigner *jose.Signer
var refusedTemplate *template.Template

func (e SimpleError) Error() string {
	return e.Err
}

func (w *LogWriter) Write(p []byte) (n int, err error) {
	xLog.Printf("%s", string(p))
	return len(p), nil
}

func processConfigError(cfgFile string, err error) {
	if err != nil {
		fmt.Printf("Can not read %s: %s\n", cfgFile, err.Error())
		os.Exit(1)
	}
}

func doErr(err error) {
	if err != nil {
		xLog.Printf("%s", tracerr.SprintSource(err, 10))
	}
}

func main() {

	defaultConfig := "gitlab-nginx-auth.yml"

	cfgFilePath := getopt.String('c', "", "Configuration file")
	helpFlag := getopt.Bool('h', "Print usage")
	testURI := getopt.String('t', "", "Debug URI matching for the specified URI")

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
	if cfg.CookieName == "" {
		cfg.CookieName = "_this_auth"
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = "/"
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 40
	}

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

	if cfg.Refused != "" {
		var err error
		refusedTemplate, err = template.ParseFiles(cfg.Refused)
		if err != nil {
			processConfigError(*cfgFilePath, err)
		}
	}

	if testURI != nil && *testURI != "" {
		patternMatched := false
		for _, acl := range cfg.AccessControl {
			if acl.Compiled.MatchString(*testURI) {
				patternMatched = true
				fmt.Printf("%s matched against %s\n", *testURI, acl.Pattern)
				for _, group := range acl.Groups {
					fmt.Printf("OK for group %s\n", group)
				}
			}
		}
		if !patternMatched {
			fmt.Printf("No pattern matched against %s\n", *testURI)
		}
		os.Exit(0)
	}

	if cfg.SignUserInfo != nil {

		kAlg := jose.SignatureAlgorithm(cfg.SignUserInfo.Algorithm)
		var keyData interface{}

		var err error
		var rawKeyData []byte

		switch kAlg {
		case jose.EdDSA, jose.ES256, jose.ES384, jose.ES512:
			rawKeyData, err = getKeyDer("EC PRIVATE KEY")
			processConfigError(*cfgFilePath, err)
			keyData, err = x509.ParseECPrivateKey(rawKeyData)
			processConfigError(*cfgFilePath, err)
			break
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			rawKeyData, err = getKeyDer("RSA PRIVATE KEY")
			processConfigError(*cfgFilePath, err)
			keyData, err = x509.ParsePKCS1PrivateKey(rawKeyData)
			processConfigError(*cfgFilePath, err)
		case jose.HS256, jose.HS384, jose.HS512:
			keyData, err = hex.DecodeString(cfg.SignUserInfo.SharedKey)
			processConfigError(*cfgFilePath, err)
		default:
			processConfigError(*cfgFilePath, SimpleError{Err: fmt.Sprintf("Unsupported key algorithm %s", kAlg)})
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: kAlg, Key: keyData}, nil)
		processConfigError(*cfgFilePath, err)
		userInfoSigner = &signer

		if cfg.SignUserInfo.HeaderName == "" {
			cfg.SignUserInfo.HeaderName = "x-signed_auth"
		}

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
		f, err := os.OpenFile(cfg.Log, os.O_WRONLY|os.O_CREATE|os.O_APPEND, os.FileMode(0644))
		processConfigError(*cfgFilePath, err)
		xLog = log.New(f, "", 0)
		//noinspection GoUnhandledErrorResult
		defer f.Close()
	}

	gin.DefaultWriter = &logWriter

	r := gin.Default()

	r.Use()

	root := r.Group(cfg.RootPath)
	root.GET("/check", func(c *gin.Context) {

		var err error

		for {

			uri := c.GetHeader("x-original-uri")
			if uri == "" {
				c.AbortWithError(400, SimpleError{Err: "No original URI header in request"})
				return
			}

			var jweCookie string
			jweCookie, err = c.Cookie(cfg.CookieName)
			if err != nil {
				break
			}
			var jwe *jose.JSONWebEncryption
			jwe, err = jose.ParseEncrypted(jweCookie)
			if err != nil {
				break
			}
			var jsonData []byte
			jsonData, err = jwe.Decrypt(key[:])
			if err != nil {
				break
			}
			authData := AuthInfo{}
			err = json.Unmarshal(jsonData, &authData)
			if err != nil {
				break
			}

			now := time.Now().Unix()
			if authData.Expiry > 0 && authData.Expiry < now {
				err = SimpleError{Err: fmt.Sprintf("token expired (at %d, now is %d), need to refresh", authData.Expiry, now)}
				break
			}

			var groups []GitlabGroup
			groups, err = getGroups(authData.Token, false)
			if err != nil {
				break
			}
			if userInfoSigner != nil {

				var user *GitlabUser
				user, err = getUserInfo(authData.Token)
				if err != nil {
					break
				}

				var groupNames []string
				for _, group := range groups {
					groupNames = append(groupNames, group.Name)
				}

				objToSign := SignedUserInfo{
					User:   *user,
					Groups: groupNames,
					Issued: uint64(now),
				}

				var bytesToSign []byte
				bytesToSign, err = json.Marshal(&objToSign)

				xLog.Printf("json to sign:%s", bytesToSign)

				if err == nil {
					var jws *jose.JSONWebSignature
					jws, err = (*userInfoSigner).Sign(bytesToSign)
					if err == nil {

						var compact string
						compact, err = jws.CompactSerialize()

						if err == nil {
							xLog.Printf("Adding header %s with %s", cfg.SignUserInfo.HeaderName, compact)
							c.Header(cfg.SignUserInfo.HeaderName, compact)
						}

					}
				}

				if err != nil {
					doErr(err)
					err = nil
				}

			}

			haveGroups := map[string]bool{}
			for _, ch := range groups {
				haveGroups[ch.Name] = true
			}

			_, patternMatched, ok := matchGroup(uri, &haveGroups)
			if ok != nil {
				xLog.Printf("Request allowed, uri %s matched pattern %s, user has group %s\n", uri, ok.Pattern, ok.Group)
				c.Status(204)
				return
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
	root.GET("/finish_login", func(c *gin.Context) {
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
			if err != nil {
				break
			}

			// check if the access token even works before
			// signalling success.

			_, err = getGroups(token.AccessToken, true)
			if err != nil {
				break
			}

			now := time.Now()
			var expireAt int64
			if token.ExpiresIn == 0 {
				expireAt = 0
			} else {
				expireAt = now.Add(time.Duration(token.ExpiresIn) * time.Second).Unix()
			}
			authInfo := AuthInfo{
				Token:  token.AccessToken,
				Expiry: expireAt,
			}

			// xLog.Printf("Token will expire in %d, set expiry to %d, now is %d", token.ExpiresIn, authInfo.Expiry, now.Unix())

			var jsonObj []byte
			jsonObj, err = json.Marshal(authInfo)
			if err != nil {
				break
			}

			var enc jose.Encrypter
			enc, err = jose.NewEncrypter(jose.A128CBC_HS256, jose.Recipient{Algorithm: jose.A256GCMKW, Key: key[:]}, nil)
			if err != nil {
				break
			}

			var jwe *jose.JSONWebEncryption
			jwe, err = enc.Encrypt(jsonObj)
			if err != nil {
				break
			}

			var jweStr string
			jweStr, err = jwe.CompactSerialize()
			if err != nil {
				break
			}

			expiresIn := token.ExpiresIn
			if expiresIn <= 0 {
				expiresIn = 100000
			}
			c.SetCookie(cfg.CookieName, jweStr, int(expiresIn), cfg.CookiePath, "", cfg.SecureCookie, true)

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

		var err error

		for {

			var myUrl *string
			myUrl, err = makeMyURL("/finish_login", nil)
			if err != nil {
				break
			}

			var rUrl *string
			rUrl, err = makeGitlabURL("/oauth/authorize", map[string]string{
				"client_id":     cfg.ClientID,
				"redirect_uri":  *myUrl,
				"scope":         "read_api",
				"state":         c.Query("from"),
				"response_type": "code",
			})

			if err != nil {
				break
			}

			c.Redirect(302, *rUrl)
			return

		}

		doErr(err)
		c.Status(500)

	})

	root.GET("/refused_login", func(c *gin.Context) {

		c.Status(403)
		var err error
		if refusedTemplate == nil {
			_, err = c.Writer.WriteString("No template configured")
		} else {

			var uri = c.Query("from")
			groups, _, _ := matchGroup(uri, nil)

			err = refusedTemplate.Execute(c.Writer, struct {
				Url    string
				Groups []string
			}{
				uri,
				groups.List(),
			})
		}
		if err != nil {
			xLog.Printf("Failed to write refusal document: %s", err.Error())
		}

	})

	xLog.Printf("Starting auth service, port %d", cfg.Port)
	err = r.Run(fmt.Sprintf("127.0.0.1:%d", cfg.Port))
	if err != nil {
		xLog.Printf("%s", err.Error())
	}

}

// anonymous structs returned : https://stackoverflow.com/a/33831833/622266

func matchGroup(uri string, haveGroups *map[string]bool) (*strset.Set, bool, *struct {
	Pattern string
	Group   string
}) {

	var patternMatched = false
	var groups = strset.New()

	for _, acl := range cfg.AccessControl {
		if acl.Compiled.MatchString(uri) {
			patternMatched = true
			for _, group := range acl.Groups {
				if haveGroups != nil {
					if _, ok := (*haveGroups)[group]; ok {
						return nil, true, &struct {
							Pattern string
							Group   string
						}{acl.Pattern, group}
					}
				} else {
					groups.Add(group)
				}
			}
		}
	}

	return groups, patternMatched, nil

}

func getKeyDer(objType string) ([]byte, error) {

	fileName := cfg.SignUserInfo.PrivateKeyFile
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, SimpleError{Err: fmt.Sprintf("Failed to read PEM data from %s - no PEM block found", fileName)}
	}
	if block.Type != objType {
		return nil, SimpleError{
			Err: fmt.Sprintf("Failed to read PEM data from %s - wanted data of type %s, got %s instead",
				fileName, objType, block.Type),
		}
	}

	return block.Bytes, nil

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
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {*myUrl},
	})

	if err != nil {
		return nil, err
	}

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
	if err != nil {
		return nil, err
	}
	return &gitlabToken, err

}

func getGroups(token string, justProbe bool) ([]GitlabGroup, error) {

	var allGroups *[]GitlabGroup
	var next *string

	for {
		var groups []GitlabGroup
		var err error

		if next == nil {
			var pageSize string
			if justProbe {
				pageSize = "1"
			} else {
				pageSize = strconv.FormatUint(uint64(cfg.PageSize), 10)
			}
			next, err = getGitLabObject(token, "/api/v4/groups", &groups,
				map[string]string{
					"min_access_level": "10",
					"per_page":         pageSize,
				})
		} else {
			next, err = getGitLabObjectFromURL(token, *next, &groups)
		}

		if err != nil {
			return nil, err
		}

		if justProbe || (next == nil && allGroups == nil) {
			return groups, nil
		}

		if allGroups == nil {
			allGroups = &groups
		} else {
			groups = append(*allGroups, groups...)
			allGroups = &groups
		}

		if next == nil {
			return *allGroups, nil
		}

	}

}

func getGitLabObjectFromURL(token string, dUrl string, into interface{}) (*string, error) {

	req, err := http.NewRequest("GET", dUrl, nil)
	if err != nil {
		return nil, err
	}
	client := http.DefaultClient
	// fmt.Printf("Authorizing with %s\n", token)
	req.Header.Add("Authorization", "BEARER "+token)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	//noinspection GoUnhandledErrorResult
	defer res.Body.Close()

	xLog.Printf("invoked %s, got %s\n", dUrl, res.Status)

	if res.StatusCode != 200 {
		return nil, SimpleError{fmt.Sprintf("Response for %s: %d", dUrl, res.StatusCode)}
	}

	d := json.NewDecoder(res.Body)
	err = d.Decode(into)
	if err != nil {
		return nil, err
	}

	if next := link.ParseHeader(res.Header)["next"]; next != nil {
		nextStr := next.String()
		return &nextStr, nil
	} else {
		return nil, nil
	}

}

func getGitLabObject(token string, path string, into interface{}, query map[string]string) (*string, error) {
	dUrl, err := urlStringWithQuery(cfg.GitLabURL, path, query)
	if err != nil {
		return nil, err
	}
	return getGitLabObjectFromURL(token, *dUrl, into)
}

func getUserInfo(token string) (*GitlabUser, error) {
	var user GitlabUser
	_, err := getGitLabObject(token, "/api/v4/user", &user, nil)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func urlWithQuery(from string, wsPath string, query map[string]string) (*url.URL, error) {
	rUrl, err := url.Parse(from)
	if err != nil {
		xLog.Printf("Error constructing request with %s/%s:%s\n", from, wsPath, err.Error())
		return nil, err
	}
	rUrl.Path = path.Join(rUrl.Path, wsPath)
	values := url.Values{}
	if query != nil {
		for k, v := range query {
			values.Add(k, v)
		}
	}
	rUrl.RawQuery = values.Encode()
	return rUrl, nil
}

func urlStringWithQuery(from string, path string, query map[string]string) (*string, error) {
	rUrl, err := urlWithQuery(from, path, query)
	if err != nil {
		return nil, err
	}
	str := rUrl.String()
	return &str, nil
}

func makeMyURL(path string, query map[string]string) (*string, error) {
	return urlStringWithQuery(cfg.CallbackURL, cfg.RootPath+path, query)
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
