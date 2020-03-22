package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/google/go-github/github"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

type Config struct {
	ClientSecret string `json:"ClientSecret"`
	ClientID     string `json:"ClientID"`
	SecretKey    string `json:"SecretKey"`
	PostRepo     string `json:"PostRepo"`
	PostUser     string `json:"PostUser"`
}

const (
	githubAuthorizeUrl = "https://github.com/login/oauth/authorize"
	githubTokenUrl     = "https://github.com/login/oauth/access_token"
	redirectUrl        = ""
)

var (
	defaultLayout string
	templateDir   string
	oauthCfg      *oauth2.Config
	store         *sessions.CookieStore
	Conf          Config
	// scopes we obv need repo but user for getting username and creating hash delete_repo for you know deleting the repo after pr because people are idiots
	scopes = []string{"repo", "user", "delete_repo"}

	tmpls = map[string]*template.Template{}
	//using PHPSESSID just for laughs
	sessionStoreKey = "PHPSESSID"
)

func index(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionStoreKey)

	if err != nil {
		fmt.Fprintln(w, err)
		return
	}

	renderData := map[string]interface{}{}

	accessToken, ok := session.Values["githubAccessToken"].(*oauth2.Token)

	if ok {

		client := github.NewClient(oauthCfg.Client(oauth2.NoContext, accessToken))
		fmt.Printf("Login succ")
		user, _, err := client.Users.Get(context.Background(), "")
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}

		renderData["github_user"] = user

	}

	tmpls["home.html"].ExecuteTemplate(w, "base", renderData)
}

func start(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 16)
	rand.Read(b)

	state := base64.URLEncoding.EncodeToString(b)

	session, _ := store.Get(r, sessionStoreKey)
	session.Values["state"] = state
	session.Save(r, w)

	url := oauthCfg.AuthCodeURL(state)
	http.Redirect(w, r, url, 302)
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionStoreKey)
	if err != nil {
		fmt.Fprintln(w, "aborted")
		return
	}

	session.Options.MaxAge = -1

	session.Save(r, w)
	http.Redirect(w, r, "/", 302)

}

//callback stuff and checking token
func callback(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionStoreKey)
	if err != nil {
		fmt.Fprintln(w, "aborted")
		return
	}

	if r.URL.Query().Get("state") != session.Values["state"] {
		fmt.Fprintln(w, "no state match; possible csrf OR cookies not enabled")
		return
	}

	token, err := oauthCfg.Exchange(oauth2.NoContext, r.URL.Query().Get("code"))
	if err != nil {
		fmt.Fprintln(w, "there was an issue getting your token")
		return
	}

	if !token.Valid() {
		fmt.Fprintln(w, "retreived invalid token")
		return
	}

	client := github.NewClient(oauthCfg.Client(oauth2.NoContext, token))

	user, _, err := client.Users.Get(context.Background(), "")
	if err != nil {
		fmt.Println(w, "error getting name")
		return
	}

	session.Values["githubUserName"] = user.Name
	session.Values["githubAccessToken"] = token
	session.Save(r, w)

	http.Redirect(w, r, "/", 302)

}

func post(w http.ResponseWriter, r *http.Request) {

	session, err := store.Get(r, sessionStoreKey)

	if err != nil {
		fmt.Fprintln(w, err)
		return
	}

	//renderData := map[string]interface{}{}

	accessToken, ok := session.Values["githubAccessToken"].(*oauth2.Token)

	if ok {
		ctx := context.Background()
		body := r.FormValue("body")
		title := r.FormValue("title")

		content := []byte(body)
		tit := []byte(title)

		client := github.NewClient(oauthCfg.Client(oauth2.NoContext, accessToken))
		_, _, err = client.Repositories.CreateFork(ctx, Conf.PostUser, Conf.PostRepo, nil)

		//it can take a while maybe i can put a sleep but for now just ignore it
		if _, oki := err.(*github.AcceptedError); oki {
			log.Println("scheduled on GitHub side")
		}

		user, _, err := client.Users.Get(context.Background(), "")

		if err != nil {
			fmt.Fprintln(w, err)
			return
		}

		//create a hash for directory name
		hash := sha1.New()
		hash.Write([]byte(user.GetName() + title))
		st := hash.Sum(nil)
		last := fmt.Sprintf("%x", st)

		//first create title file
		opts := &github.RepositoryContentFileOptions{
			Message: github.String(title),
			Content: tit,
			Branch:  github.String("master"),
			//	Author:    &github.CommitAuthor{Name: user.Name, Email: user.Email, Login: user.Login},
			//	Committer: &github.CommitAuthor{Name: user.Name, Email: user.Email, Login: user.Login},
		}

		_, _, err = client.Repositories.CreateFile(ctx, user.GetLogin(), Conf.PostRepo, last+"/TITLE.md", opts)

		if err != nil {
			fmt.Fprintln(w, err)
			return
		}

		opts = &github.RepositoryContentFileOptions{
			Message: github.String(title),
			Content: content,
			Branch:  github.String("master"),
			//	Author:    &github.CommitAuthor{Name: user.Name, Email: user.Email, Login: user.Login},
			//	Committer: &github.CommitAuthor{Name: user.Name, Email: user.Email, Login: user.Login},
		}

		//now content
		_, _, err = client.Repositories.CreateFile(ctx, user.GetLogin(), Conf.PostRepo, last+"/README.md", opts)

		if err != nil {
			fmt.Fprintln(w, err)
			return
		}

		newPR := &github.NewPullRequest{
			Title:               github.String("New post by " + user.GetLogin()),
			Head:                github.String(fmt.Sprintf("%s:master", user.GetLogin())),
			Base:                github.String("master"),
			Body:                github.String(title),
			MaintainerCanModify: github.Bool(true),
		}

		pr, _, err := client.PullRequests.Create(context.Background(), Conf.PostUser, Conf.PostRepo, newPR)

		if err != nil {
			fmt.Fprintln(w, err)
			return
		}

		fmt.Printf("PR created: %s\n", pr.GetHTMLURL())

		_, err = client.Repositories.Delete(ctx, user.GetLogin(), Conf.PostRepo)

		if err != nil {
			fmt.Fprintln(w, err)
			return
		}

		http.Redirect(w, r, "/", 302)

	}

}

func init() {
	gob.Register(&oauth2.Token{})
}

func main() {
	defaultLayout = os.Getenv("POSTHUB_BASE") + "/templates/layout.html"
	templateDir = os.Getenv("POSTHUB_BASE") + "/templates/"
	//set template stuff
	tmpls["home.html"] = template.Must(template.ParseFiles(templateDir+"home.html", defaultLayout))

	//read conf variables

	Conf.ClientID = os.Getenv("POSTHUB_CLIENT_ID")
	Conf.ClientSecret = os.Getenv("POSTHUB_CLIENT_SECRET")
	Conf.PostRepo = os.Getenv("POSTHUB_POST_REPO")
	Conf.PostUser = os.Getenv("POSTHUB_POST_USER")
	Conf.SecretKey = os.Getenv("POSTHUB_SECRET_KEY")

	store = sessions.NewCookieStore([]byte(Conf.SecretKey)) //authKey) //, encKey)

	oauthCfg = &oauth2.Config{
		ClientID:     Conf.ClientID,
		ClientSecret: Conf.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  githubAuthorizeUrl,
			TokenURL: githubTokenUrl,
		},
		RedirectURL: redirectUrl,
		Scopes:      scopes,
	}

	r := mux.NewRouter()
	r.HandleFunc("/", index)
	//they are .php because
	r.HandleFunc("/bang.php", start)
	r.HandleFunc("/callback.php", callback)
	r.HandleFunc("/sendpost.php", post)
	r.HandleFunc("/logout.php", logout)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.Handle("/", r)

	//default port
	listenAddr := "0.0.0.0:8080"

	envPort := os.Getenv("PORT")
	if len(envPort) > 0 {
		listenAddr = ":" + envPort
	}

	log.Printf("attempting listen on %s", listenAddr)
	log.Fatalln(http.ListenAndServe(listenAddr, nil))

}
