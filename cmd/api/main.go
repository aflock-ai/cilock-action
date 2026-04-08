package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/lib/pq"

	"github.com/testifysec/dropbox-clone/internal/auth"
	"github.com/testifysec/dropbox-clone/internal/config"
	"github.com/testifysec/dropbox-clone/internal/file"
	"github.com/testifysec/dropbox-clone/internal/group"
	"github.com/testifysec/dropbox-clone/internal/user"
)

func main() {
	ctx := context.Background()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect to database
	db, err := sql.Open("postgres", cfg.Database.URL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	db.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	db.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)

	// Verify database connection
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Println("Connected to database")

	// Initialize S3 storage
	s3Storage, err := file.NewS3Storage(ctx, &file.S3Config{
		Bucket:          cfg.S3.Bucket,
		Region:          cfg.S3.Region,
		Endpoint:        cfg.S3.Endpoint,
		AccessKeyID:     cfg.S3.AccessKeyID,
		SecretAccessKey: cfg.S3.SecretAccessKey,
		UsePathStyle:    cfg.S3.UsePathStyle || cfg.S3.Endpoint != "",
	})
	if err != nil {
		log.Fatalf("Failed to initialize S3 storage: %v", err)
	}
	log.Println("Initialized S3 storage")

	// Initialize repositories
	userRepo := user.NewPostgresRepository(db)
	groupRepo := group.NewPostgresRepository(db)
	fileRepo := file.NewPostgresRepository(db)

	// Initialize services
	userService := user.NewService(userRepo)
	groupService := group.NewService(groupRepo)
	fileService := file.NewService(fileRepo, s3Storage, groupService)

	// Initialize JWT service
	jwtService := auth.NewJWTService(
		cfg.JWT.Secret,
		cfg.JWT.AccessTokenTTL,
		cfg.JWT.RefreshTokenTTL,
		cfg.JWT.Issuer,
	)

	// Initialize handlers
	authHandler := auth.NewHandler(userService, jwtService)
	groupHandler := group.NewHandler(groupService)
	fileHandler := file.NewHandler(fileService)

	// Setup router
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Serve static files (frontend)
	staticDir := http.Dir("./static")
	fileServer := http.FileServer(staticDir)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/index.html")
	})
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Auth routes (public)
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", authHandler.Register)
			r.Post("/login", authHandler.Login)
			r.Post("/refresh", authHandler.Refresh)
		})

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(auth.Middleware(jwtService))

			// Group routes
			r.Route("/groups", func(r chi.Router) {
				r.Post("/", groupHandler.Create)
				r.Get("/", groupHandler.List)
				r.Route("/{groupId}", func(r chi.Router) {
					r.Post("/members", groupHandler.AddMember)
					r.Delete("/members/{userId}", groupHandler.RemoveMember)

					// File routes
					r.Route("/files", func(r chi.Router) {
						r.Post("/", fileHandler.Upload)
						r.Get("/", fileHandler.List)
						r.Get("/{fileId}", fileHandler.Download)
						r.Delete("/{fileId}", fileHandler.Delete)
					})
				})
			})
		})
	})

	// Server configuration
	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Graceful shutdown
	go func() {
		log.Printf("Starting server on port %s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server exited")
}
