package artifacts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"

	"github.com/nektos/act/pkg/common"
)

type FileContainerResourceURL struct {
	FileContainerResourceURL string `json:"fileContainerResourceUrl"`
}

type NamedFileContainerResourceURL struct {
	Name                     string `json:"name"`
	FileContainerResourceURL string `json:"fileContainerResourceUrl"`
}

type NamedFileContainerResourceURLResponse struct {
	Count int                             `json:"count"`
	Value []NamedFileContainerResourceURL `json:"value"`
}

type ContainerItem struct {
	Path            string `json:"path"`
	ItemType        string `json:"itemType"`
	ContentLocation string `json:"contentLocation"`
}

type ContainerItemResponse struct {
	Value []ContainerItem `json:"value"`
}

type ResponseMessage struct {
	Message string `json:"message"`
}

type WritableFile interface {
	io.WriteCloser
}

type WriteFS interface {
	OpenWritable(name string) (WritableFile, error)
	OpenAppendable(name string) (WritableFile, error)
}

type readWriteFSImpl struct {
}

func (fwfs readWriteFSImpl) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func (fwfs readWriteFSImpl) OpenWritable(name string) (WritableFile, error) {
	if err := os.MkdirAll(filepath.Dir(name), os.ModePerm); err != nil {
		return nil, err
	}
	return os.OpenFile(name, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
}

func (fwfs readWriteFSImpl) OpenAppendable(name string) (WritableFile, error) {
	if err := os.MkdirAll(filepath.Dir(name), os.ModePerm); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o644)

	if err != nil {
		return nil, err
	}

	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	return file, nil
}

var gzipExtension = ".gz__"

func safeResolve(baseDir string, relPath string) string {
	return filepath.Join(baseDir, filepath.Clean(filepath.Join(string(os.PathSeparator), relPath)))
}

func uploads(router *httprouter.Router, baseDir string, fsys WriteFS) {
	router.POST("/_apis/pipelines/workflows/:runId/artifacts", func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		runID := params.ByName("runId")

		json, err := json.Marshal(FileContainerResourceURL{
			FileContainerResourceURL: fmt.Sprintf("http://%s/upload/%s", req.Host, runID),
		})
		if err != nil {
			panic(err)
		}

		_, err = w.Write(json)
		if err != nil {
			panic(err)
		}
	})

	router.PUT("/upload/:runId", func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		itemPath := req.URL.Query().Get("itemPath")
		runID := params.ByName("runId")

		if req.Header.Get("Content-Encoding") == "gzip" {
			itemPath += gzipExtension
		}

		safeRunPath := safeResolve(baseDir, runID)
		safePath := safeResolve(safeRunPath, itemPath)

		file, err := func() (WritableFile, error) {
			contentRange := req.Header.Get("Content-Range")
			if contentRange != "" && !strings.HasPrefix(contentRange, "bytes 0-") {
				return fsys.OpenAppendable(safePath)
			}
			return fsys.OpenWritable(safePath)
		}()

		if err != nil {
			panic(err)
		}
		defer file.Close()

		writer, ok := file.(io.Writer)
		if !ok {
			panic(errors.New("File is not writable"))
		}

		if req.Body == nil {
			panic(errors.New("No body given"))
		}

		_, err = io.Copy(writer, req.Body)
		if err != nil {
			panic(err)
		}

		json, err := json.Marshal(ResponseMessage{
			Message: "success",
		})
		if err != nil {
			panic(err)
		}

		_, err = w.Write(json)
		if err != nil {
			panic(err)
		}
	})

	router.PATCH("/_apis/pipelines/workflows/:runId/artifacts", func(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
		json, err := json.Marshal(ResponseMessage{
			Message: "success",
		})
		if err != nil {
			panic(err)
		}

		_, err = w.Write(json)
		if err != nil {
			panic(err)
		}
	})
}

func downloads(router *httprouter.Router, baseDir string, fsys fs.FS) {
	router.GET("/_apis/pipelines/workflows/:runId/artifacts", func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		runID := params.ByName("runId")

		safePath := safeResolve(baseDir, runID)

		entries, err := fs.ReadDir(fsys, safePath)
		if err != nil {
			panic(err)
		}

		var list []NamedFileContainerResourceURL
		for _, entry := range entries {
			list = append(list, NamedFileContainerResourceURL{
				Name:                     entry.Name(),
				FileContainerResourceURL: fmt.Sprintf("http://%s/download/%s", req.Host, runID),
			})
		}

		json, err := json.Marshal(NamedFileContainerResourceURLResponse{
			Count: len(list),
			Value: list,
		})
		if err != nil {
			panic(err)
		}

		_, err = w.Write(json)
		if err != nil {
			panic(err)
		}
	})

	router.GET("/download/:container", func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		container := params.ByName("container")
		itemPath := req.URL.Query().Get("itemPath")
		safePath := safeResolve(baseDir, filepath.Join(container, itemPath))

		var files []ContainerItem
		err := fs.WalkDir(fsys, safePath, func(path string, entry fs.DirEntry, _ error) error {
			if !entry.IsDir() {
				rel, err := filepath.Rel(safePath, path)
				if err != nil {
					panic(err)
				}

				// if it was upload as gzip
				rel = strings.TrimSuffix(rel, gzipExtension)
				path := filepath.Join(itemPath, rel)

				rel = filepath.ToSlash(rel)
				path = filepath.ToSlash(path)

				files = append(files, ContainerItem{
					Path:            path,
					ItemType:        "file",
					ContentLocation: fmt.Sprintf("http://%s/artifact/%s/%s/%s", req.Host, container, itemPath, rel),
				})
			}
			return nil
		})
		if err != nil {
			panic(err)
		}

		json, err := json.Marshal(ContainerItemResponse{
			Value: files,
		})
		if err != nil {
			panic(err)
		}

		_, err = w.Write(json)
		if err != nil {
			panic(err)
		}
	})

	router.GET("/artifact/*path", func(w http.ResponseWriter, _ *http.Request, params httprouter.Params) {
		path := params.ByName("path")[1:]

		safePath := safeResolve(baseDir, path)

		file, err := fsys.Open(safePath)
		if err != nil {
			// try gzip file
			file, err = fsys.Open(safePath + gzipExtension)
			if err != nil {
				panic(err)
			}
			w.Header().Add("Content-Encoding", "gzip")
		}

		_, err = io.Copy(w, file)
		if err != nil {
			panic(err)
		}
	})
}

func oidcRoutes(router *httprouter.Router, keyManager common.OIDCKeyManager) {
	// Token handler shared by GET and POST — GitHub Actions API uses GET,
	// some clients use POST.
	tokenHandler := func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		// Get bearer token from Authorization header
		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "unauthorized: missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Parse the request token to get GitHub context
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "unauthorized: invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		ctx, err := common.ParseOIDCRequestToken(parts[1])
		if err != nil {
			http.Error(w, fmt.Sprintf("unauthorized: %v", err), http.StatusUnauthorized)
			return
		}

		// Get audience from query parameter
		audience := req.URL.Query().Get("audience")
		if audience == "" {
			audience = "https://github.com/" + ctx.RepositoryOwner
		}

		// Generate OIDC ID token
		idToken, err := common.GenerateOIDCToken(keyManager, ctx, audience)
		if err != nil {
			http.Error(w, fmt.Sprintf("error generating token: %v", err), http.StatusInternalServerError)
			return
		}

		// Return GitHub-style response
		response := map[string]interface{}{
			"count": 1,
			"value": idToken,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
	router.GET("/token", tokenHandler)
	router.POST("/token", tokenHandler)

	// GET /.well-known/jwks - Publish public keys
	router.GET("/.well-known/jwks", func(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
		jwks, err := common.GenerateJWKS(keyManager)
		if err != nil {
			http.Error(w, fmt.Sprintf("error generating JWKS: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(jwks); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

func Serve(ctx context.Context, artifactPath string, addr string, port string, keyManager common.OIDCKeyManager) context.CancelFunc {
	serverContext, cancel := context.WithCancel(ctx)
	logger := common.Logger(serverContext)

	if artifactPath == "" {
		return cancel
	}

	router := httprouter.New()

	logger.Debugf("Artifacts base path '%s'", artifactPath)
	fsys := readWriteFSImpl{}
	uploads(router, artifactPath, fsys)
	downloads(router, artifactPath, fsys)
	RoutesV4(router, artifactPath, fsys, fsys)

	// Add OIDC routes if keyManager is provided
	if keyManager != nil {
		oidcRoutes(router, keyManager)
		logger.Info("OIDC token endpoints enabled")
	}

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", addr, port),
		ReadHeaderTimeout: 2 * time.Second,
		Handler:           router,
	}

	// run server
	go func() {
		logger.Infof("Start server on http://%s:%s", addr, port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal(err)
		}
	}()

	// wait for cancel to gracefully shutdown server
	go func() {
		<-serverContext.Done()

		if err := server.Shutdown(ctx); err != nil {
			logger.Errorf("Failed shutdown gracefully - force shutdown: %v", err)
			server.Close()
		}
	}()

	return cancel
}
